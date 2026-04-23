/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Global Log Classifier (GLC) v2.0
 *  Wadjet-Eye AI Platform
 *
 *  The FIRST stage of the Global Detection Pipeline.
 *  Every ingested event MUST pass through here before any rule
 *  evaluation or MITRE mapping occurs.
 *
 *  Responsibilities:
 *   1. Classify the telemetry domain of every event
 *      (windows_security | linux | firewall | web | database |
 *       network | dns | endpoint | unknown)
 *   2. Attach immutable _meta block with domain, sub-domain,
 *      confidence, and source fingerprint.
 *   3. Enforce Logsource Gate — reject rule candidates whose
 *      logsource domain is incompatible with the event's domain.
 *   4. Normalize field aliases across platforms into canonical names
 *      so downstream modules need no per-domain logic.
 *
 *  Design principles:
 *   • Deterministic — identical input → identical classification.
 *   • Immutable metadata — downstream may not modify _meta.domain.
 *   • Zero-false-positive bias — when uncertain, classify 'unknown'
 *     rather than guess; unknown events pass only generic rules.
 *
 *  Public API:
 *   GLC.classify(event)                → event (with _meta attached)
 *   GLC.classifyBatch(events)          → events[]
 *   GLC.isRuleCompatible(rule, event)  → boolean
 *   GLC.getMetrics()                   → MetricsObject
 *
 *  backend/services/raykan/global-log-classifier.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
//  DOMAIN DEFINITIONS
// ─────────────────────────────────────────────────────────────────────────────
const DOMAINS = {
  WINDOWS_SECURITY : 'windows_security',
  WINDOWS_SYSTEM   : 'windows_system',
  WINDOWS_PROCESS  : 'windows_process',
  LINUX            : 'linux',
  FIREWALL         : 'firewall',
  WEB              : 'web',
  DATABASE         : 'database',
  NETWORK          : 'network',
  DNS              : 'dns',
  ENDPOINT         : 'endpoint',
  CLOUD            : 'cloud',
  UNKNOWN          : 'unknown',
};

// ─────────────────────────────────────────────────────────────────────────────
//  DOMAIN CLASSIFIERS
//  Applied in priority order — first match wins.
// ─────────────────────────────────────────────────────────────────────────────

/** Windows Security Event Log — EventID-based classification */
const WINDOWS_SECURITY_EVENT_IDS = new Set([
  // Authentication
  '4624','4625','4626','4627','4634','4647','4648','4649',
  '4650','4651','4652','4653','4654','4655','4656','4657',
  // Account management
  '4720','4722','4723','4724','4725','4726','4727','4728',
  '4729','4730','4731','4732','4733','4734','4735','4740',
  '4741','4742','4743','4744','4745','4746','4747','4748',
  '4749','4750','4751','4752','4753','4754','4755','4756',
  '4757','4758','4759','4760','4761','4762','4763','4765',
  '4766','4767','4781','4782','4793','4798','4799',
  // Logon/Logoff extended
  '4768','4769','4770','4771','4772','4776','4777',
  // Object access
  '4663','4656','4660','4670','4985',
  // Privilege use
  '4672','4673','4674',
  // Policy change
  '4702','4703','4704','4705','4706','4707','4713','4715','4716',
  '4717','4718','4719','4720','4739','4864','4865','4866','4867',
  // Process tracking — also in Windows_Process but linked to Security channel
  '4688','4689','4696','4697','4698','4699','4700','4701',
  // Audit log management
  '1102','1100','4614','4616','4621','4657',
]);

const WINDOWS_PROCESS_EVENT_IDS = new Set([
  '4688','4689','1','10','11','12','13','14','15','17','18','22',
  '25','26','29','255',
]);

const WINDOWS_SYSTEM_EVENT_IDS = new Set([
  '7045','7036','7040','7034','104','6005','6006','6008',
  '41','1074','1076',
]);

const SECURITY_CHANNELS = new Set([
  'security', 'microsoft-windows-security-auditing',
  'system', 'microsoft-windows-system',
  'application', 'microsoft-windows-application',
]);

/** Windows Security EventID channel detection */
function _isWindowsSecurity(evt) {
  const eid = String(evt.eventId || evt.raw?.EventID || evt.EventID || '');
  const ch  = (evt.channel || evt.raw?.Channel || evt.Channel || '').toLowerCase();
  const src = (evt.source  || '').toLowerCase();

  if (WINDOWS_SECURITY_EVENT_IDS.has(eid)) return { domain: DOMAINS.WINDOWS_SECURITY, confidence: 0.99, subDomain: _winSecSubDomain(eid) };
  if (WINDOWS_SYSTEM_EVENT_IDS.has(eid))   return { domain: DOMAINS.WINDOWS_SYSTEM,   confidence: 0.95, subDomain: 'system_events' };
  if (ch.includes('security') || src.includes('winevt:security')) return { domain: DOMAINS.WINDOWS_SECURITY, confidence: 0.90, subDomain: 'auth' };
  if (ch.includes('system'))               return { domain: DOMAINS.WINDOWS_SYSTEM,   confidence: 0.85, subDomain: 'system_events' };
  return null;
}

function _winSecSubDomain(eid) {
  const n = parseInt(eid, 10);
  if ([4624,4625,4626,4627,4634,4647,4648,4649,4768,4769,4770,4771,4776].includes(n)) return 'authentication';
  if (n >= 4720 && n <= 4799) return 'account_management';
  if ([4672,4673,4674].includes(n))   return 'privilege_use';
  if ([4688,4689].includes(n))        return 'process_creation';
  if ([4697,4698,4699,4700,4701].includes(n)) return 'scheduled_task';
  return 'windows_security_misc';
}

/** Windows Process Telemetry (Sysmon + Process Tracking) */
function _isWindowsProcess(evt) {
  const eid = String(evt.eventId || evt.raw?.EventID || '');
  const ch  = (evt.channel || evt.raw?.Channel || '').toLowerCase();
  const src = (evt.source  || '').toLowerCase();

  // EID 22 is Sysmon DNS event — yield to _isDns classifier
  if (eid === '22' && (ch.includes('sysmon') || ch.includes('microsoft-windows-sysmon') || src.includes('sysmon'))) {
    return null; // Let _isDns handle it
  }

  if (WINDOWS_PROCESS_EVENT_IDS.has(eid) && (ch.includes('sysmon') || ch.includes('microsoft-windows-sysmon')))
    return { domain: DOMAINS.WINDOWS_PROCESS, confidence: 0.99, subDomain: 'sysmon' };
  if (eid === '4688' || eid === '4689')
    return { domain: DOMAINS.WINDOWS_PROCESS, confidence: 0.95, subDomain: 'process_tracking' };
  if (src.includes('sysmon') || ch.includes('sysmon'))
    return { domain: DOMAINS.WINDOWS_PROCESS, confidence: 0.95, subDomain: 'sysmon' };
  return null;
}

/** Linux / Unix telemetry */
const LINUX_INDICATORS = [
  /syslog/i, /auth\.log/i, /secure$/i, /\/var\/log\//i, /messages$/i,
  /sshd/i, /sudo/i, /cron/i, /auditd/i, /journald/i, /dmesg/i,
  /pam_unix/i, /su\[/i, /useradd/i, /userdel/i,
];

function _isLinux(evt) {
  const src  = (evt.source   || '').toLowerCase();
  const prog = (evt.program  || evt.raw?.program || evt.raw?.appname || '').toLowerCase();
  const msg  = (evt.message  || evt.raw?.message || '').toLowerCase();
  const fmt  = (evt.format   || '').toLowerCase();

  if (fmt === 'syslog' || fmt === 'linux') return { domain: DOMAINS.LINUX, confidence: 0.95, subDomain: _linuxSubDomain(prog, msg, src) };

  // Check program names
  const knownLinuxProgs = ['sshd','sudo','cron','crond','su','useradd','userdel','passwd',
                           'bash','sh','auditd','systemd','dmesg','kernel','pam_unix','login'];
  if (knownLinuxProgs.some(p => prog.startsWith(p))) return { domain: DOMAINS.LINUX, confidence: 0.95, subDomain: _linuxSubDomain(prog, msg, src) };

  // Syslog-format event IDs or source patterns
  if (LINUX_INDICATORS.some(rx => rx.test(src))) return { domain: DOMAINS.LINUX, confidence: 0.90, subDomain: _linuxSubDomain(prog, msg, src) };

  return null;
}

function _linuxSubDomain(prog, msg, src) {
  if (/sshd/.test(prog) || /ssh/.test(src))           return 'ssh';
  if (/sudo/.test(prog))                               return 'sudo';
  if (/cron/.test(prog) || /cron/.test(src))           return 'cron';
  if (/audit/.test(prog) || /audit/.test(src))         return 'auditd';
  if (/useradd|userdel|passwd|usermod/.test(prog))     return 'account_management';
  if (/pam_unix|login|su\b/.test(prog))                return 'authentication';
  return 'linux_misc';
}

/** Firewall / Network Security logs */
const FIREWALL_INDICATORS = [
  /iptables/i, /netfilter/i, /pf\b/i, /ipfw/i, /nftables/i,
  /cisco.asa/i, /fortigate/i, /checkpoint/i, /paloalto/i,
  /windows.firewall/i, /wf\.msc/i, /netsh.advfirewall/i,
  /\bfw\b/i, /firewall/i,
];

const FIREWALL_FIELDS = ['action','direction','protocol','src_ip','dst_ip',
                          'src_port','dst_port','in_interface','out_interface',
                          'packets','bytes_sent','bytes_recv','rule_id','policy'];

function _isFirewall(evt) {
  const src = (evt.source || '').toLowerCase();
  const fmt = (evt.format || '').toLowerCase();
  const raw = evt.raw || {};

  if (fmt === 'firewall' || fmt === 'cef_firewall') return { domain: DOMAINS.FIREWALL, confidence: 0.99, subDomain: 'firewall_generic' };
  if (FIREWALL_INDICATORS.some(rx => rx.test(src))) return { domain: DOMAINS.FIREWALL, confidence: 0.95, subDomain: _fwSubDomain(src) };

  // Windows Firewall EventIDs
  const eid = String(evt.eventId || raw.EventID || '');
  if (['5152','5153','5154','5155','5156','5157','5158','5159'].includes(eid))
    return { domain: DOMAINS.FIREWALL, confidence: 0.99, subDomain: 'windows_firewall' };

  // CEF-style firewall field detection
  const hasFirewallFields = FIREWALL_FIELDS.filter(f => raw[f] != null || evt[f] != null).length >= 3;
  if (hasFirewallFields && (raw.src_ip || raw.dst_ip || evt.srcIp || evt.dstIp))
    return { domain: DOMAINS.FIREWALL, confidence: 0.85, subDomain: 'network_firewall' };

  return null;
}

function _fwSubDomain(src) {
  if (/cisco.asa|asa/.test(src))     return 'cisco_asa';
  if (/fortigate|forti/.test(src))   return 'fortigate';
  if (/paloalto|pan/.test(src))      return 'paloalto';
  if (/checkpoint/.test(src))        return 'checkpoint';
  if (/iptables|nftables/.test(src)) return 'linux_firewall';
  return 'firewall_generic';
}

/** Web Server logs (Apache, Nginx, IIS, etc.) */
const WEB_HTTP_METHODS = new Set(['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS','CONNECT','TRACE']);

function _isWeb(evt) {
  const src = (evt.source  || '').toLowerCase();
  const fmt = (evt.format  || '').toLowerCase();
  const raw = evt.raw      || {};

  // Source-explicit check first (highest specificity)
  if (/apache|nginx|iis|httpd|lighttpd|caddy|haproxy/.test(src))
    return { domain: DOMAINS.WEB, confidence: 0.99, subDomain: _webSubDomain(src, fmt) };
  if (fmt === 'web' || fmt === 'webserver' || fmt === 'iis' || fmt === 'apache' || fmt === 'nginx')
    return { domain: DOMAINS.WEB, confidence: 0.99, subDomain: _webSubDomain(src, fmt) };

  // IIS W3C fields (field-based detection — use source-derived sub-domain)
  if (raw['cs-method'] || raw['cs-uri-stem'] || raw['cs-uri-query'] || raw['sc-status'])
    return { domain: DOMAINS.WEB, confidence: 0.99, subDomain: _webSubDomain(src, fmt) || 'iis' };

  // Common log format / combined log format
  if (evt.url || evt.uri || evt.httpMethod || evt.statusCode ||
      raw.request || raw.method || raw.status_code)
    return { domain: DOMAINS.WEB, confidence: 0.95, subDomain: _webSubDomain(src, fmt) };

  // Check for HTTP method in raw
  const method = (raw.method || raw['cs-method'] || evt.httpMethod || '').toUpperCase();
  if (WEB_HTTP_METHODS.has(method)) return { domain: DOMAINS.WEB, confidence: 0.85, subDomain: _webSubDomain(src, fmt) };

  return null;
}

function _webSubDomain(src, fmt) {
  if (/apache|httpd/.test(src) || fmt === 'apache')   return 'apache';
  if (/nginx/.test(src)        || fmt === 'nginx')     return 'nginx';
  if (/iis/.test(src)          || fmt === 'iis')       return 'iis';
  if (/lighttpd/.test(src))                            return 'lighttpd';
  if (/caddy/.test(src))                               return 'caddy';
  if (/haproxy/.test(src))                             return 'haproxy';
  return 'web_generic';
}

/** Database logs */
const DB_INDICATORS = [
  /mysql/i, /postgresql/i, /postgres/i, /mssql/i, /sqlserver/i,
  /oracle/i, /mongodb/i, /redis/i, /cassandra/i, /sqlite/i,
  /mariadb/i, /db2/i,
];

const DB_FIELDS = ['query','sql_statement','database','table_name','schema',
                    'rows_affected','query_duration','db_user','sql_command'];

function _isDatabase(evt) {
  const src = (evt.source || '').toLowerCase();
  const raw = evt.raw     || {};

  if (DB_INDICATORS.some(rx => rx.test(src))) return { domain: DOMAINS.DATABASE, confidence: 0.95, subDomain: _dbSubDomain(src) };
  const hasDbFields = DB_FIELDS.filter(f => raw[f] != null || evt[f] != null).length >= 2;
  if (hasDbFields) return { domain: DOMAINS.DATABASE, confidence: 0.85, subDomain: 'db_generic' };

  return null;
}

function _dbSubDomain(src) {
  if (/mysql/.test(src))                    return 'mysql';
  if (/postgresql|postgres/.test(src))      return 'postgresql';
  if (/mssql|sqlserver/.test(src))          return 'mssql';
  if (/oracle/.test(src))                   return 'oracle';
  if (/mongodb/.test(src))                  return 'mongodb';
  if (/redis/.test(src))                    return 'redis';
  if (/mariadb/.test(src))                  return 'mariadb';
  return 'db_generic';
}

/** DNS logs */
function _isDns(evt) {
  const src = (evt.source || '').toLowerCase();
  const fmt = (evt.format || '').toLowerCase();
  const raw = evt.raw     || {};
  const eid = String(evt.eventId || raw.EventID || '');

  if (eid === '22' && (src.includes('sysmon') || (evt.channel||'').toLowerCase().includes('sysmon')))
    return { domain: DOMAINS.DNS, confidence: 0.99, subDomain: 'sysmon_dns' };
  if (['5157','5159'].includes(eid) && raw.ProcessName) return null; // firewall
  if (fmt === 'dns' || src.includes('dns'))
    return { domain: DOMAINS.DNS, confidence: 0.95, subDomain: 'dns_generic' };
  if (raw.QueryName || raw.query_name || evt.domain || raw.dns_query)
    return { domain: DOMAINS.DNS, confidence: 0.90, subDomain: 'dns_generic' };

  return null;
}

/** Generic network telemetry */
function _isNetwork(evt) {
  const src = (evt.source || '').toLowerCase();
  const raw = evt.raw     || {};

  const hasNetFields = (raw.src_ip || raw.srcIp || raw.source_ip) &&
                       (raw.dst_ip || raw.dstIp || raw.destination_ip);
  if (hasNetFields) return { domain: DOMAINS.NETWORK, confidence: 0.80, subDomain: 'network_flow' };
  if (/netflow|zeek|bro\b|pcap|snmp|nids/.test(src))
    return { domain: DOMAINS.NETWORK, confidence: 0.90, subDomain: 'network_generic' };

  return null;
}

/** Cloud (AWS CloudTrail, Azure Audit, GCP, etc.) */
function _isCloud(evt) {
  const src = (evt.source || '').toLowerCase();
  const raw = evt.raw     || {};

  if (raw.eventSource?.includes('.amazonaws.com') || src.includes('cloudtrail'))
    return { domain: DOMAINS.CLOUD, confidence: 0.99, subDomain: 'aws_cloudtrail' };
  if (raw.operationName || src.includes('azure'))
    return { domain: DOMAINS.CLOUD, confidence: 0.95, subDomain: 'azure_activity' };
  if (src.includes('gcp') || raw.protoPayload)
    return { domain: DOMAINS.CLOUD, confidence: 0.95, subDomain: 'gcp_audit' };

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
//  CLASSIFIER PIPELINE (ordered — most specific first)
// ─────────────────────────────────────────────────────────────────────────────
const CLASSIFIER_PIPELINE = [
  _isDns,              // before WindowsProcess — Sysmon EID 22 is DNS, not process
  _isWindowsProcess,   // before security — Sysmon EventID 1 check is more specific
  _isWindowsSecurity,
  _isWeb,
  _isDatabase,
  _isFirewall,
  _isLinux,
  _isCloud,
  _isNetwork,
];

// ─────────────────────────────────────────────────────────────────────────────
//  LOGSOURCE GATE RULES
//  Maps Sigma logsource `category` / `product` / `service` to allowed domains.
//  A rule's logsource is incompatible if its required domain does not match
//  the event's classified domain.
// ─────────────────────────────────────────────────────────────────────────────
const LOGSOURCE_DOMAIN_MAP = {
  // Windows
  'windows'              : [DOMAINS.WINDOWS_SECURITY, DOMAINS.WINDOWS_PROCESS, DOMAINS.WINDOWS_SYSTEM],
  'windows_security'     : [DOMAINS.WINDOWS_SECURITY],
  'process_creation'     : [DOMAINS.WINDOWS_PROCESS, DOMAINS.LINUX, DOMAINS.ENDPOINT],
  'ps_script'            : [DOMAINS.WINDOWS_PROCESS, DOMAINS.ENDPOINT],
  'ps_module'            : [DOMAINS.WINDOWS_PROCESS, DOMAINS.ENDPOINT],
  'registry_add'         : [DOMAINS.WINDOWS_PROCESS, DOMAINS.WINDOWS_SECURITY],
  'registry_delete'      : [DOMAINS.WINDOWS_PROCESS, DOMAINS.WINDOWS_SECURITY],
  'registry_set'         : [DOMAINS.WINDOWS_PROCESS, DOMAINS.WINDOWS_SECURITY],
  'registry_event'       : [DOMAINS.WINDOWS_PROCESS, DOMAINS.WINDOWS_SECURITY],
  'driver_load'          : [DOMAINS.WINDOWS_PROCESS],
  'image_load'           : [DOMAINS.WINDOWS_PROCESS],
  'network_connection'   : [DOMAINS.NETWORK, DOMAINS.WINDOWS_PROCESS, DOMAINS.FIREWALL, DOMAINS.DNS],
  'network_traffic'      : [DOMAINS.NETWORK, DOMAINS.FIREWALL],
  'pipe_created'         : [DOMAINS.WINDOWS_PROCESS],
  'create_remote_thread' : [DOMAINS.WINDOWS_PROCESS],
  'raw_access_read'      : [DOMAINS.WINDOWS_PROCESS],
  'file_event'           : [DOMAINS.WINDOWS_PROCESS, DOMAINS.LINUX, DOMAINS.ENDPOINT],
  'file_delete'          : [DOMAINS.WINDOWS_PROCESS, DOMAINS.LINUX, DOMAINS.ENDPOINT],
  'file_access'          : [DOMAINS.WINDOWS_PROCESS, DOMAINS.LINUX],

  // Web
  'webserver'            : [DOMAINS.WEB],
  'web'                  : [DOMAINS.WEB],
  'iis'                  : [DOMAINS.WEB],
  'apache'               : [DOMAINS.WEB],
  'nginx'                : [DOMAINS.WEB],
  'proxy'                : [DOMAINS.WEB, DOMAINS.NETWORK],

  // Network / Firewall
  'firewall'             : [DOMAINS.FIREWALL],
  'dns'                  : [DOMAINS.DNS],
  'zeek'                 : [DOMAINS.NETWORK],
  'netflow'              : [DOMAINS.NETWORK],

  // Linux / Unix
  'linux'                : [DOMAINS.LINUX],
  'syslog'               : [DOMAINS.LINUX, DOMAINS.NETWORK, DOMAINS.FIREWALL],
  'auditd'               : [DOMAINS.LINUX],
  'auth'                 : [DOMAINS.LINUX, DOMAINS.WINDOWS_SECURITY],

  // Database
  'database'             : [DOMAINS.DATABASE],
  'mssql'                : [DOMAINS.DATABASE],
  'mysql'                : [DOMAINS.DATABASE],
  'postgresql'           : [DOMAINS.DATABASE],

  // Cloud
  'aws'                  : [DOMAINS.CLOUD],
  'azure'                : [DOMAINS.CLOUD],
  'gcp'                  : [DOMAINS.CLOUD],
  'cloudtrail'           : [DOMAINS.CLOUD],
};

// ─────────────────────────────────────────────────────────────────────────────
//  CROSS-DOMAIN COMPATIBLE RULE CATEGORIES
//  These logsource categories are too generic to gate on domain alone.
// ─────────────────────────────────────────────────────────────────────────────
const CROSS_DOMAIN_CATEGORIES = new Set([
  'generic', 'application', 'endpoint', 'network_connection',
  'network_traffic',
]);

// ─────────────────────────────────────────────────────────────────────────────
//  FIELD NORMALIZATION MAP
//  Canonical field name → list of source-specific aliases.
//  GLC resolves aliases to canonical names during classification.
// ─────────────────────────────────────────────────────────────────────────────
const FIELD_ALIASES = {
  // Identity
  user        : ['User','TargetUserName','username','user_name','SubjectUserName','win_user','cs-username'],
  srcUser     : ['SubjectUserName','AccountName','src_user','source_user'],
  dstUser     : ['TargetUserName','dest_user','target_user'],

  // Network
  srcIp       : ['SourceIp','IpAddress','src_ip','source_ip','c-ip','ClientIP','sourceIPv4Address'],
  dstIp       : ['DestIp','dst_ip','dest_ip','destination_ip','s-ip','ServerIP','destinationIPv4Address'],
  srcPort     : ['SourcePort','src_port','c-port','ClientPort','sourcePort'],
  dstPort     : ['DestPort','dst_port','s-port','ServerPort','destinationPort'],
  protocol    : ['Protocol','proto','network_protocol'],
  direction   : ['Direction','traffic_direction'],

  // Process
  process     : ['Image','Process','ProcessName','CommandName','exe','process_name','FileName','comm'],
  parentProc  : ['ParentImage','ParentProcessName','parent_image','ppid_name','ParentCommandLine'],
  commandLine : ['CommandLine','command_line','cmdline','ProcessCommandLine','argv','cmd'],
  processId   : ['ProcessId','pid','ProcessID','process_id'],
  parentPid   : ['ParentProcessId','ppid','ParentProcessID'],
  integrityLevel: ['IntegrityLevel','integrity_level'],

  // Web
  httpMethod  : ['cs-method','method','http_method','request_method','verb'],
  url         : ['cs-uri-stem','RequestURI','url','uri','request_url','http_uri'],
  urlQuery    : ['cs-uri-query','QueryString','url_query','query_string'],
  statusCode  : ['sc-status','status_code','http_status','response_code','Status'],
  userAgent   : ['cs(User-Agent)','user_agent','http_user_agent','UserAgent'],
  referer     : ['cs(Referer)','referer','http_referer'],
  bytesIn     : ['cs-bytes','bytes_in','request_size'],
  bytesOut    : ['sc-bytes','bytes_out','response_size','bytes'],

  // Auth
  logonType   : ['LogonType','logon_type','login_type'],
  authPackage : ['AuthenticationPackageName','AuthPackage','authentication_protocol'],
  eventId     : ['EventID','event_id','EventCode','event_code'],

  // Common
  computer    : ['Computer','hostname','host','Workstation','machine','node'],
  domain      : ['Domain','QueryName','dns_query','domain_name'],
  timestamp   : ['TimeGenerated','EventTime','timestamp','@timestamp','time','date'],
  message     : ['Message','message','msg','log_message'],
  severity    : ['Level','severity','level','alert_level'],
  channel     : ['Channel','channel','log_name','source_name'],
};

// ─────────────────────────────────────────────────────────────────────────────
//  METRICS
// ─────────────────────────────────────────────────────────────────────────────
const _metrics = {
  classified       : 0,
  domain_breakdown : {},
  gate_blocked     : 0,
  gate_allowed     : 0,
  normalization_applied: 0,
};

function _trackDomain(domain) {
  _metrics.classified++;
  _metrics.domain_breakdown[domain] = (_metrics.domain_breakdown[domain] || 0) + 1;
}

// ─────────────────────────────────────────────────────────────────────────────
//  CORE: classify(event)
//  Runs the classifier pipeline and attaches _meta to the event.
// ─────────────────────────────────────────────────────────────────────────────
function classify(event) {
  if (!event || typeof event !== 'object') {
    return { _meta: _buildMeta(DOMAINS.UNKNOWN, 'unknown', 0, 'invalid_input') };
  }

  // If already classified, return unchanged (idempotent)
  if (event._meta?.classified === true) return event;

  // Run classifiers in priority order
  let result = null;
  for (const classifier of CLASSIFIER_PIPELINE) {
    result = classifier(event);
    if (result) break;
  }

  const { domain, confidence, subDomain } = result || {
    domain: DOMAINS.UNKNOWN, confidence: 0.0, subDomain: 'unknown',
  };

  _trackDomain(domain);

  // Build canonical _meta (frozen to prevent downstream mutation)
  const meta = _buildMeta(domain, subDomain, confidence, null);

  // Normalize field aliases to canonical names
  const normalized = _normalizeFields(event);

  // Attach meta (using Object.defineProperty so it shows in JSON but cannot be overwritten)
  Object.defineProperty(normalized, '_meta', {
    value: Object.freeze(meta),
    writable: false,
    enumerable: true,
    configurable: false,
  });

  return normalized;
}

function _buildMeta(domain, subDomain, confidence, note) {
  return {
    domain,
    subDomain,
    confidence,
    classified: true,
    classifiedAt: new Date().toISOString(),
    note,
  };
}

/**
 * Resolve field aliases into canonical names without losing raw data.
 * Creates evt.canonical = { user, srcIp, dstIp, … } for CEA / BCE use.
 */
function _normalizeFields(event) {
  if (event._canonicalized) return event;

  const raw = event.raw || event;
  const canonical = {};

  for (const [canonName, aliases] of Object.entries(FIELD_ALIASES)) {
    // Check top-level event first
    if (event[canonName] != null) {
      canonical[canonName] = event[canonName];
      continue;
    }
    // Then check raw block
    for (const alias of aliases) {
      const val = raw[alias] ?? event[alias];
      if (val != null) {
        canonical[canonName] = val;
        break;
      }
    }
  }

  // Promote important canonical fields to top-level for backwards compat
  const promoted = ['user','srcIp','dstIp','process','commandLine','eventId',
                     'computer','logonType','authPackage','url','httpMethod'];
  for (const f of promoted) {
    if (canonical[f] != null && event[f] == null) {
      event[f] = canonical[f];
    }
  }

  event._canonical    = canonical;
  event._canonicalized = true;
  _metrics.normalization_applied++;

  return event;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Batch classify
// ─────────────────────────────────────────────────────────────────────────────
function classifyBatch(events) {
  if (!Array.isArray(events)) return [];
  return events.map(classify);
}

// ─────────────────────────────────────────────────────────────────────────────
//  LOGSOURCE GATE
//  Returns true if the rule's logsource is compatible with the event's domain.
//  Rules with cross-domain logsource categories bypass the gate.
// ─────────────────────────────────────────────────────────────────────────────
function isRuleCompatible(rule, event) {
  const eventDomain = event?._meta?.domain;
  if (!eventDomain || eventDomain === DOMAINS.UNKNOWN) return true; // unclassified → pass

  const ls = rule?.logsource || {};
  const category = (ls.category || '').toLowerCase();
  const product  = (ls.product  || '').toLowerCase();
  const service  = (ls.service  || '').toLowerCase();

  // Cross-domain categories bypass the gate
  if (CROSS_DOMAIN_CATEGORIES.has(category)) return true;
  if (!category && !product && !service)     return true; // no logsource → pass

  // Gather allowed domains from category, product, service
  const allowed = new Set();
  for (const key of [category, product, service]) {
    const domains = LOGSOURCE_DOMAIN_MAP[key] || [];
    domains.forEach(d => allowed.add(d));
  }

  // If no mapping found, allow (generous for unknown logsource combos)
  if (allowed.size === 0) return true;

  const compatible = allowed.has(eventDomain);
  if (compatible) _metrics.gate_allowed++;
  else            _metrics.gate_blocked++;

  return compatible;
}

// ─────────────────────────────────────────────────────────────────────────────
//  DOMAIN HELPERS  (used by CEA / BCE)
// ─────────────────────────────────────────────────────────────────────────────
function getDomain(event) {
  return event?._meta?.domain || DOMAINS.UNKNOWN;
}

function isWindowsDomain(event) {
  const d = getDomain(event);
  return d === DOMAINS.WINDOWS_SECURITY || d === DOMAINS.WINDOWS_PROCESS || d === DOMAINS.WINDOWS_SYSTEM;
}

function isLinuxDomain(event)    { return getDomain(event) === DOMAINS.LINUX; }
function isWebDomain(event)      { return getDomain(event) === DOMAINS.WEB; }
function isFirewallDomain(event) { return getDomain(event) === DOMAINS.FIREWALL; }
function isDatabaseDomain(event) { return getDomain(event) === DOMAINS.DATABASE; }
function isDnsDomain(event)      { return getDomain(event) === DOMAINS.DNS; }
function isNetworkDomain(event)  { return getDomain(event) === DOMAINS.NETWORK; }

function getMetrics() {
  return { ...JSON.parse(JSON.stringify(_metrics)) };
}

function resetMetrics() {
  _metrics.classified       = 0;
  _metrics.domain_breakdown = {};
  _metrics.gate_blocked     = 0;
  _metrics.gate_allowed     = 0;
  _metrics.normalization_applied = 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXPORTS
// ─────────────────────────────────────────────────────────────────────────────
module.exports = {
  // Core API
  classify,
  classifyBatch,
  isRuleCompatible,

  // Domain helpers
  getDomain,
  isWindowsDomain,
  isLinuxDomain,
  isWebDomain,
  isFirewallDomain,
  isDatabaseDomain,
  isDnsDomain,
  isNetworkDomain,

  // Metrics
  getMetrics,
  resetMetrics,

  // Constants
  DOMAINS,
  LOGSOURCE_DOMAIN_MAP,
  FIELD_ALIASES,
};
