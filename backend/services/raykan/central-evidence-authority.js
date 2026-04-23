/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Central Evidence Authority (CEA) v1.0
 *
 *  The single, immutable gate that ALL ATT&CK technique assignments
 *  must pass before they may appear in any detection, report, or
 *  narrative.  No downstream module (sigma, AI, MITRE-mapper, route
 *  handlers, narrative builders) may override a CEA decision.
 *
 *  Design principles:
 *   1. Deterministic — same input always produces same output.
 *   2. Strict — technique is suppressed unless evidence is positive.
 *   3. Centralised — one source of truth; never duplicated.
 *   4. Auditable — every decision is logged with a reason code.
 *   5. Non-bypassable — enforced at the earliest possible point and
 *      re-enforced at MITRE-mapper output stage as a final guard.
 *
 *  Evidence gates per technique:
 *   • T1190  — Exploit Public-Facing App → web-server telemetry required
 *   • T1021  — Remote Services          → remote-execution evidence required
 *   • T1021.002 — SMB/Admin Shares      → SMB port / PsExec / admin-share path
 *   • T1021.006 — WinRM                 → WinRM process / port 5985-5986
 *   • T1550.002 — Pass-the-Hash         → cross-host NTLM correlation
 *   • T1110   — Brute Force             → ≥3 failed logons (4625)
 *   • T1110.001 — Password Guessing     → ≥3 failed logons
 *   • T1110.003 — Password Spraying     → ≥3 target users across failures
 *   • T1136   — Account Creation        → net user /add or group-add EventID
 *   • T1189   — Drive-by Compromise     → web/proxy telemetry required
 *   • T1071.001 — Web Protocols C2      → network/proxy telemetry
 *   • T1071.004 — DNS C2               → DNS telemetry
 *
 *  Public API:
 *   CEA.validateTechnique(tid, evidence)   → { allowed, reason, alternative }
 *   CEA.validateDetection(detection, ctx)  → detection (tags rewritten)
 *   CEA.validateBatch(detections, events)  → detections[] (FPs removed/adjusted)
 *   CEA.buildEvidence(events, detections)  → EvidenceContext object
 *   CEA.getAuditLog()                      → Array<AuditEntry>
 *   CEA.getMetrics()                       → MetricsObject
 *   CEA.resetAuditLog()                    → void
 *
 *  backend/services/raykan/central-evidence-authority.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────────────────────
//  HARD EVIDENCE REQUIREMENTS
//  Each entry defines the conditions that MUST be satisfied for the technique
//  to be assigned.  requiresAny: at least one item in the array must be true.
// ─────────────────────────────────────────────────────────────────────────────
const TECHNIQUE_EVIDENCE_RULES = {

  // ── T1190 — Exploit Public-Facing Application ─────────────────────────────
  // Must have web-server telemetry evidence.
  'T1190': {
    label: 'Exploit Public-Facing Application',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'has_webserver_logs' },
      { type: 'process_match',  field: 'parentProc',  values: ['w3wp.exe', 'httpd.exe', 'nginx.exe', 'php.exe', 'apache.exe', 'tomcat.exe', 'iisexpress.exe', 'lighttpd.exe'] },
      { type: 'logsource_cat',  categories: ['webserver', 'web', 'iis', 'apache', 'nginx', 'http'] },
      { type: 'field_present',  field: 'url' },
      { type: 'field_present',  field: 'raw.cs-uri-stem' },
      { type: 'field_present',  field: 'raw.cs-method' },
    ],
    suppressedAlternative: null,
    reason: 'T1190 requires web-server process parent or HTTP telemetry',
  },

  // ── T1189 — Drive-by Compromise ───────────────────────────────────────────
  'T1189': {
    label: 'Drive-by Compromise',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'has_webserver_logs' },
      { type: 'logsource_cat',  categories: ['webserver', 'web', 'proxy', 'http'] },
      { type: 'field_present',  field: 'url' },
    ],
    suppressedAlternative: null,
    reason: 'T1189 requires web/proxy telemetry',
  },

  // ── T1021 — Remote Services (parent technique) ────────────────────────────
  'T1021': {
    label: 'Remote Services',
    requiresAny: [
      { type: 'process_match',  field: 'process',    values: ['psexec.exe', 'psexec64.exe', 'winrm.cmd', 'wmic.exe', 'mstsc.exe'] },
      { type: 'process_match',  field: 'commandLine', values: ['psexec', '\\\\\\\\', 'winrm', 'wmic /node', 'invoke-command'] },
      { type: 'evidence_flag',  flag: 'multi_host_activity' },
      { type: 'port_match',     ports: ['445', '3389', '5985', '5986', '22'] },
    ],
    suppressedAlternative: null,
    reason: 'T1021 requires concrete remote-service evidence',
  },

  // ── T1021.002 — SMB / Windows Admin Shares ───────────────────────────────
  'T1021.002': {
    label: 'SMB/Windows Admin Shares Lateral Movement',
    requiresAny: [
      { type: 'process_match',  field: 'process',    values: ['psexec.exe', 'psexec64.exe'] },
      { type: 'cmd_contains',   field: 'commandLine', values: ['\\\\\\\\', 'admin$', 'ipc$', 'c$', 'd$', 'e$', 'psexec'] },
      { type: 'cmd_contains',   field: 'raw.ShareName',  values: ['admin$', 'ipc$', 'c$'] },
      { type: 'cmd_contains',   field: 'raw.ObjectName', values: ['\\\\admin$', '\\\\c$', '\\\\ipc$'] },
      { type: 'port_match',     ports: ['445'] },
      { type: 'evidence_flag',  flag: 'multi_host_activity' },
    ],
    suppressedAlternative: null,
    reason: 'T1021.002 requires SMB/admin-share evidence — LogonType=3 alone is insufficient',
  },

  // ── T1021.001 — Remote Desktop Protocol ──────────────────────────────────
  'T1021.001': {
    label: 'Remote Desktop Protocol',
    requiresAny: [
      { type: 'process_match',  field: 'process',  values: ['mstsc.exe', 'rdpclip.exe', 'tstheme.exe'] },
      { type: 'port_match',     ports: ['3389'] },
      { type: 'logon_type',     types: ['10'] }, // RemoteInteractive
    ],
    suppressedAlternative: null,
    reason: 'T1021.001 requires RDP process or port 3389',
  },

  // ── T1021.006 — Windows Remote Management ────────────────────────────────
  'T1021.006': {
    label: 'Windows Remote Management',
    requiresAny: [
      { type: 'process_match',  field: 'process',    values: ['wsmprovhost.exe', 'winrm.cmd'] },
      { type: 'process_match',  field: 'parentProc', values: ['wsmprovhost.exe'] },
      { type: 'port_match',     ports: ['5985', '5986'] },
      { type: 'channel_match',  channels: ['microsoft-windows-winrm/operational'] },
    ],
    suppressedAlternative: null,
    reason: 'T1021.006 requires WinRM process/port evidence',
  },

  // ── T1550.002 — Pass-the-Hash ─────────────────────────────────────────────
  // LogonType=3 + NTLM alone is NEVER sufficient; requires cross-host evidence
  'T1550.002': {
    label: 'Pass-the-Hash',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'cross_host_ntlm_logon' },
      { type: 'cmd_contains',   field: 'commandLine', values: ['sekurlsa::pth', '-pth', 'wce -s', 'pass.*hash', 'ntlm.*hash', 'pth-winexe', 'mimikatz'] },
    ],
    suppressedAlternative: 'T1078',
    reason: 'T1550.002 (PtH) requires cross-host NTLM evidence; single-host LogonType=3+NTLM → T1078',
  },

  // ── T1110 — Brute Force ───────────────────────────────────────────────────
  'T1110': {
    label: 'Brute Force',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'multiple_4625_events' },
      { type: 'cmd_contains',   field: 'commandLine', values: ['hydra', 'medusa', 'ncrack', 'crowbar', '-password', '-spray'] },
    ],
    suppressedAlternative: 'T1078',
    reason: 'T1110 requires ≥3 failed logon events; single 4625 → T1078',
  },

  // ── T1110.001 — Password Guessing ─────────────────────────────────────────
  'T1110.001': {
    label: 'Password Guessing',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'multiple_4625_events' },
    ],
    suppressedAlternative: 'T1078',
    reason: 'T1110.001 requires multiple (≥3) failed logon events',
  },

  // ── T1110.003 — Password Spraying ─────────────────────────────────────────
  'T1110.003': {
    label: 'Password Spraying',
    requiresAny: [
      { type: 'evidence_flag',  flag: 'multiple_target_users' },
    ],
    suppressedAlternative: 'T1078',
    reason: 'T1110.003 requires ≥3 distinct target usernames across failures',
  },

  // ── T1136 — Account Creation ──────────────────────────────────────────────
  'T1136': {
    label: 'Account Creation',
    requiresAny: [
      { type: 'cmd_contains',   field: 'commandLine', values: ['net user', 'net localgroup', '/add', 'useradd', 'New-LocalUser', 'Add-LocalGroupMember'] },
      { type: 'event_id',       ids: ['4720', '4722', '4728', '4732', '4756'] },
    ],
    suppressedAlternative: null,
    reason: 'T1136 requires account-creation command or Windows account-management EventID',
  },

  // ── T1136.001 — Local Account ─────────────────────────────────────────────
  'T1136.001': {
    label: 'Create Local Account',
    requiresAny: [
      { type: 'cmd_contains',   field: 'commandLine', values: ['net user', '/add', 'useradd', 'New-LocalUser'] },
      { type: 'event_id',       ids: ['4720'] },
    ],
    suppressedAlternative: null,
    reason: 'T1136.001 requires local account-creation command or EventID 4720',
  },

  // ── T1071.001 — Web Protocols (C2) ────────────────────────────────────────
  'T1071.001': {
    label: 'Application Layer Protocol: Web Protocols',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['network_connection', 'proxy', 'web', 'http'] },
      { type: 'evidence_flag',  flag: 'has_webserver_logs' },
      { type: 'port_match',     ports: ['80', '443', '8080', '8443'] },
    ],
    suppressedAlternative: null,
    reason: 'T1071.001 requires network/proxy telemetry or HTTP port evidence',
  },

  // ── T1071.004 — DNS (C2) ──────────────────────────────────────────────────
  'T1071.004': {
    label: 'Application Layer Protocol: DNS',
    requiresAny: [
      { type: 'logsource_cat',  categories: ['dns', 'network_connection'] },
      { type: 'field_present',  field: 'domain' },
    ],
    suppressedAlternative: null,
    reason: 'T1071.004 requires DNS or network telemetry',
  },
};

// ─────────────────────────────────────────────────────────────────────────────
//  INVALID TECHNIQUE → LOGSOURCE COMBINATIONS
//  Technique CANNOT be assigned when the ONLY evidence is from these sources.
//  This blocks auto-generated rules that match authentication events (4624/4625)
//  for web/lateral-movement techniques.
// ─────────────────────────────────────────────────────────────────────────────
const TECHNIQUE_BLOCKED_SOURCES = {
  // Web techniques must never fire on pure Windows auth events
  'T1190': {
    blockedEventIds:   new Set(['4624', '4625', '4626', '4627', '4648', '4768', '4769', '4776']),
    blockedLogsources: new Set(['security', 'system', 'application']),
    description: 'Web exploitation techniques must not match Windows authentication events',
    exceptWhen: ['has_webserver_logs', 'has_web_parent_process'],
  },
  'T1189': {
    blockedEventIds:   new Set(['4624', '4625', '4648', '4768', '4769']),
    blockedLogsources: new Set(['security', 'system', 'application']),
    description: 'Drive-by technique must not match Windows authentication events',
    exceptWhen: ['has_webserver_logs'],
  },
};

// Auth-event IDs that indicate normal logon activity (not lateral movement alone)
const AUTH_ONLY_EVENT_IDS = new Set(['4624', '4625', '4626', '4627', '4634', '4647', '4648',
                                      '4720', '4726', '4728', '4732', '4756', '4768', '4769', '4776']);

// ─────────────────────────────────────────────────────────────────────────────
//  KEYWORD-BASED RULE DETECTION
//  Rules that use keyword selectors matching technique names are unreliable.
// ─────────────────────────────────────────────────────────────────────────────
const TECHNIQUE_KEYWORD_PATTERNS = [
  /exploit.public.facing/i, /t1190/i,
  /smb.windows.admin/i,     /t1021\.002/i,
  /pass.the.hash/i,         /t1550\.002/i,
  /brute.force/i,           /t1110/i,
  /lateral.movement/i,
];

function isKeywordOnlyRule(rule) {
  const det = rule.detection || {};
  const sel = det.selection || {};
  // Rule uses only keyword-based detection (no field matching)
  if (sel.keywords != null && Object.keys(sel).every(k => k === 'keywords' || k === 'condition')) {
    return true;
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  EVIDENCE CONTEXT
//  Derived from the event batch — computed ONCE per ingest call and passed
//  to all technique evaluations.
// ─────────────────────────────────────────────────────────────────────────────
class EvidenceContext {
  constructor(events = [], detections = []) {
    this._events     = Array.isArray(events)     ? events     : [];
    this._detections = Array.isArray(detections) ? detections : [];
    this._flags      = null; // lazy
  }

  get flags() {
    if (!this._flags) this._flags = this._buildFlags();
    return this._flags;
  }

  hasFlag(flag) { return !!this.flags[flag]; }

  _buildFlags() {
    const flags = {};
    const evts = this._events;

    // 4625 / 4624 event counts
    const failures  = evts.filter(e => String(e.eventId || e.raw?.EventID) === '4625');
    const successes = evts.filter(e => String(e.eventId || e.raw?.EventID) === '4624');

    flags.multiple_4625_events = failures.length >= 3;
    flags.has_4624_success     = successes.length > 0;

    // Multiple target users (password spray)
    const targetUsers = new Set(
      failures.map(e => (e.raw?.TargetUserName || e.user || '').toLowerCase()).filter(Boolean)
    );
    flags.multiple_target_users = targetUsers.size >= 3;

    // Multi-host: ≥2 distinct computers
    const computers = new Set(evts.map(e => (e.computer || e.raw?.Computer || '').toLowerCase()).filter(Boolean));
    flags.multi_host_activity = computers.size >= 2;

    // Web-server telemetry
    flags.has_webserver_logs = evts.some(e => {
      const src  = (e.source || '').toLowerCase();
      const fmt  = (e.format || '').toLowerCase();
      const chan  = (e.channel || e.raw?.Channel || '').toLowerCase();
      return src.includes('web') || src.includes('iis') || src.includes('apache') ||
             src.includes('nginx') || src.includes('http') ||
             fmt === 'webserver' ||
             chan.includes('w3svc') || chan.includes('httpd') ||
             e.url != null || e.raw?.['cs-uri-stem'] != null || e.raw?.['cs-method'] != null;
    });

    // Web-server as parent process (for web-shell detection)
    flags.has_web_parent_process = evts.some(e => {
      const pp = (e.parentProc || e.raw?.ParentImage || '').toLowerCase();
      return /w3wp|httpd|nginx|php|apache|tomcat|iisexpress|lighttpd/.test(pp);
    });

    // Cross-host NTLM logons (PtH indicator)
    const ntlmLogons = successes.filter(e => {
      const lt = String(e.raw?.LogonType || e.logonType || '');
      const ap = (e.raw?.AuthPackage || e.raw?.AuthenticationPackageName || '').toUpperCase();
      return lt === '3' && ap === 'NTLM';
    });
    if (ntlmLogons.length > 0) {
      const ntlmComputers = new Set(ntlmLogons.map(e => (e.computer || e.raw?.Computer || '').toLowerCase()).filter(Boolean));
      const ntlmSrcIps    = new Set(ntlmLogons.map(e => (e.srcIp || e.raw?.IpAddress || '').toLowerCase()).filter(v => v && v !== '-' && v !== '127.0.0.1' && v !== '::1'));
      flags.cross_host_ntlm_logon = ntlmComputers.size >= 2 || ntlmSrcIps.size >= 2;
    } else {
      flags.cross_host_ntlm_logon = false;
    }

    return flags;
  }

  // Convenience: check if a single event has a web-server parent process
  static eventHasWebParent(evt) {
    const pp = (evt?.parentProc || evt?.raw?.ParentImage || '').toLowerCase();
    return /w3wp|httpd|nginx|php|apache|tomcat|iisexpress|lighttpd/.test(pp);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  AUDIT LOG  (ring buffer, max 10 000 entries)
// ─────────────────────────────────────────────────────────────────────────────
const MAX_AUDIT_ENTRIES = 10_000;
const _auditLog = [];
const _metrics  = {
  total_evaluated    : 0,
  allowed            : 0,
  suppressed         : 0,
  downgraded         : 0,
  blocked_source     : 0,
  keyword_blocked    : 0,
  fp_reason_breakdown: {},
};

function _audit(entry) {
  if (_auditLog.length >= MAX_AUDIT_ENTRIES) _auditLog.shift();
  _auditLog.push({ ts: new Date().toISOString(), ...entry });
}

function _trackMetric(key, reason) {
  _metrics[key] = (_metrics[key] || 0) + 1;
  _metrics.total_evaluated++;
  if (reason) {
    _metrics.fp_reason_breakdown[reason] = (_metrics.fp_reason_breakdown[reason] || 0) + 1;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  CORE: validateTechnique
//  Evaluates a single technique against evidence context and optional event.
//
//  @param {string}  tid            — ATT&CK technique ID (e.g. 'T1190')
//  @param {Object}  evidenceCtx    — EvidenceContext instance
//  @param {Object}  [event]        — normalized event (optional)
//  @param {Object}  [detection]    — detection object (optional — for logsource)
//  @param {Object}  [ruleCtx]      — { logsource, ruleId } for logsource checks
//  @returns {{ allowed: boolean, reason: string, alternative: string|null }}
// ─────────────────────────────────────────────────────────────────────────────
function validateTechnique(tid, evidenceCtx, event = {}, detection = {}, ruleCtx = {}) {
  const rules = TECHNIQUE_EVIDENCE_RULES[tid];
  const evt   = event || {};
  const raw   = evt.raw || {};

  // ── Gate 0: Blocked source check ──────────────────────────────────────────
  // Certain technique/EventID combinations are absolutely invalid.
  const blockedSrc = TECHNIQUE_BLOCKED_SOURCES[tid];
  if (blockedSrc) {
    const evtId       = String(evt.eventId || raw.EventID || '');
    const ruleService = (ruleCtx.logsource?.service || detection.logsource?.service || '').toLowerCase();
    const isBlockedId = evtId && blockedSrc.blockedEventIds.has(evtId);
    const isBlockedLS = ruleService && blockedSrc.blockedLogsources.has(ruleService);

    if (isBlockedId || isBlockedLS) {
      // Check exceptions
      const exceptionSatisfied = (blockedSrc.exceptWhen || []).some(f => evidenceCtx.hasFlag(f));
      if (!exceptionSatisfied) {
        const reason = `${tid} blocked: ${blockedSrc.description} (eventId=${evtId}, logsource=${ruleService})`;
        _audit({ tid, decision: 'blocked_source', reason, ruleId: ruleCtx.ruleId || detection.ruleId });
        _trackMetric('blocked_source', `blocked_source:${tid}`);
        return { allowed: false, reason, alternative: null };
      }
    }
  }

  // ── Gate 1: Keyword-only rule check ───────────────────────────────────────
  // Keyword rules matching technique names produce too many FPs.
  if (ruleCtx.isKeywordRule) {
    const reason = `${tid} blocked: keyword-only detection rule (no field matching)`;
    _audit({ tid, decision: 'keyword_blocked', reason, ruleId: ruleCtx.ruleId || detection.ruleId });
    _trackMetric('keyword_blocked', `keyword_rule:${tid}`);
    return { allowed: false, reason, alternative: null };
  }

  // ── Gate 2: Evidence requirement check ────────────────────────────────────
  if (!rules) {
    // No evidence requirements defined — allow through
    _trackMetric('allowed', null);
    return { allowed: true, reason: `${tid} has no CEA evidence requirements — allowed`, alternative: null };
  }

  const satisfied = rules.requiresAny.some(req => _checkEvidenceReq(req, evidenceCtx, evt, raw, detection, ruleCtx));

  if (!satisfied) {
    const reason = rules.reason;
    const alt    = rules.suppressedAlternative;
    _audit({ tid, decision: alt ? 'downgraded' : 'suppressed', reason, alternative: alt, ruleId: ruleCtx.ruleId || detection.ruleId });
    _trackMetric(alt ? 'downgraded' : 'suppressed', `evidence_missing:${tid}`);
    return { allowed: false, reason, alternative: alt };
  }

  _audit({ tid, decision: 'allowed', ruleId: ruleCtx.ruleId || detection.ruleId });
  _trackMetric('allowed', null);
  return { allowed: true, reason: `${tid} evidence requirements satisfied`, alternative: null };
}

// ─────────────────────────────────────────────────────────────────────────────
//  EVIDENCE REQUIREMENT CHECKER
// ─────────────────────────────────────────────────────────────────────────────
function _checkEvidenceReq(req, ctx, evt, raw, detection, ruleCtx) {
  switch (req.type) {

    case 'evidence_flag':
      return ctx.hasFlag(req.flag);

    case 'process_match': {
      const val = String(_getField(req.field, evt, raw) || '').toLowerCase();
      return req.values.some(v => val.includes(v.toLowerCase()) || val.endsWith(v.toLowerCase()));
    }

    case 'cmd_contains': {
      const val = String(_getField(req.field, evt, raw) || '').toLowerCase();
      return req.values.some(v => val.includes(v.toLowerCase()));
    }

    case 'port_match': {
      const dstPort = String(evt.dstPort || raw.DestinationPort || raw.dst_port || '');
      return req.ports.includes(dstPort);
    }

    case 'logon_type': {
      const lt = String(evt.logonType || raw.LogonType || '');
      return req.types.includes(lt);
    }

    case 'logsource_cat': {
      const ruleLS  = (ruleCtx.logsource?.category || detection.logsource?.category || '').toLowerCase();
      const ruleLS2 = (ruleCtx.logsource?.service  || detection.logsource?.service  || '').toLowerCase();
      const evtSrc  = (evt.source  || '').toLowerCase();
      const evtFmt  = (evt.format  || '').toLowerCase();
      const evtChan = (evt.channel || raw.Channel || '').toLowerCase();
      return req.categories.some(cat =>
        ruleLS.includes(cat) || ruleLS2.includes(cat) ||
        evtSrc.includes(cat) || evtFmt.includes(cat)  ||
        evtChan.includes(cat)
      );
    }

    case 'field_present': {
      const val = _getField(req.field, evt, raw);
      return val != null && val !== '';
    }

    case 'event_id': {
      const evtId = String(evt.eventId || raw.EventID || '');
      return req.ids.includes(evtId);
    }

    case 'channel_match': {
      const chan = (evt.channel || raw.Channel || '').toLowerCase();
      return req.channels.some(c => chan.includes(c.toLowerCase()));
    }

    default:
      return false;
  }
}

// Dot-notation field resolver with raw fallback
function _getField(fieldPath, evt, raw) {
  if (!fieldPath) return null;
  const parts = fieldPath.split('.');
  let val = evt;
  for (const p of parts) {
    if (val == null) return null;
    if (p === 'raw') val = raw;
    else val = val[p];
  }
  if (val != null) return val;
  // Try raw directly
  val = raw;
  for (const p of parts) {
    if (val == null) return null;
    val = val[p];
  }
  return val;
}

// ─────────────────────────────────────────────────────────────────────────────
//  validateDetection
//  Applies CEA to a single detection object.  Rewrites tags in place,
//  never adding techniques — only removing or downgrading unsupported ones.
//
//  The CEA decision is FINAL — no downstream module may re-add a suppressed
//  technique (enforced by the _ceaValidated flag + MITRE-mapper guard).
// ─────────────────────────────────────────────────────────────────────────────
function validateDetection(detection, evidenceCtx) {
  if (!detection || typeof detection !== 'object') return detection;

  const tags       = Array.isArray(detection.tags) ? detection.tags : [];
  const logsource  = detection.logsource || {};
  const event      = detection.event || {};
  const ruleCtx    = {
    ruleId       : detection.ruleId,
    logsource,
    isKeywordRule: isKeywordOnlyRule(detection),
  };

  // Extract technique IDs from tags
  const taggedTechniques = [];
  for (const tag of tags) {
    const m = tag.toLowerCase().match(/attack\.(t\d+(?:\.\d+)?)/);
    if (m) taggedTechniques.push(m[1].toUpperCase());
  }

  if (taggedTechniques.length === 0) {
    // No ATT&CK tags — pass through, mark as validated
    return { ...detection, _ceaValidated: true, _ceaWarnings: [] };
  }

  const finalTechniques = [];
  const warnings        = [];

  for (const tid of taggedTechniques) {
    const result = validateTechnique(tid, evidenceCtx, event, detection, ruleCtx);
    if (result.allowed) {
      finalTechniques.push(tid);
    } else {
      warnings.push(result.reason);
      if (result.alternative) {
        // Only add alternative if not already in the set
        if (!finalTechniques.includes(result.alternative)) {
          finalTechniques.push(result.alternative);
          warnings.push(`  → downgraded to ${result.alternative}`);
        }
      }
    }
  }

  const uniqueFinal = [...new Set(finalTechniques)];
  const hadChanges  = uniqueFinal.join(',') !== taggedTechniques.join(',');

  if (!hadChanges) {
    return { ...detection, _ceaValidated: true, _ceaWarnings: [] };
  }

  // Rebuild tags: keep non-technique tags + rewrite technique tags
  const nonTechTags = tags.filter(t => !t.toLowerCase().match(/attack\.t\d+/));
  const newTechTags = uniqueFinal.map(t => `attack.${t.toLowerCase()}`);
  const newTags     = [...nonTechTags, ...newTechTags];

  // Reduce confidence proportionally to suppressed techniques
  const suppressedCount = taggedTechniques.length - uniqueFinal.filter(t => taggedTechniques.includes(t)).length;
  const ratio      = taggedTechniques.length > 0 ? uniqueFinal.length / taggedTechniques.length : 1;
  const newConf    = uniqueFinal.length === 0
    ? Math.max(5, (detection.confidence || 70) - 40)
    : Math.round((detection.confidence || 70) * (0.6 + 0.4 * ratio));

  return {
    ...detection,
    tags          : newTags,
    confidence    : newConf,
    _ceaValidated : true,
    _ceaAdjusted  : true,
    _ceaOrigTags  : tags,
    _ceaFinalTids : uniqueFinal,
    _ceaWarnings  : warnings,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  validateBatch
//  Applies CEA to all detections in a batch.
//  Suppresses detections where ALL techniques were removed AND the detection
//  has no other meaningful content.
//
//  @param {Array}  detections   — array of detection objects
//  @param {Array}  events       — normalized events in the same ingestion call
//  @returns {Array}             — filtered + adjusted detections
// ─────────────────────────────────────────────────────────────────────────────
function validateBatch(detections = [], events = []) {
  const detArr = Array.isArray(detections) ? detections : [];
  const evtArr = Array.isArray(events)     ? events     : [];

  // Build EvidenceContext once for the whole batch
  const ctx     = new EvidenceContext(evtArr, detArr);
  const result  = [];

  for (const det of detArr) {
    // Skip already-validated objects (idempotent)
    if (det._ceaValidated) {
      result.push(det);
      continue;
    }

    const validated = validateDetection(det, ctx);

    // Suppress detection only when:
    //  a) ALL tagged techniques were removed, AND
    //  b) The detection's ONLY claim was via those techniques (pure tag-based),
    //  c) There is no structural evidence in the event itself (e.g. actual PsExec process)
    if (validated._ceaAdjusted && validated._ceaFinalTids?.length === 0) {
      const origTids = (validated._ceaOrigTags || [])
        .map(t => { const m = t.match(/attack\.(t\d+(?:\.\d+)?)/i); return m ? m[1].toUpperCase() : null; })
        .filter(Boolean);

      // Only suppress entirely if ALL techniques were purely tag-based with no field evidence
      const allRequireEvidence = origTids.every(t => TECHNIQUE_EVIDENCE_RULES[t] != null);
      if (allRequireEvidence && origTids.length > 0) {
        console.warn(
          `[CEA] Suppressed detection "${det.ruleName || det.title || det.ruleId}": ` +
          `all techniques (${origTids.join(', ')}) lack supporting evidence`
        );
        continue; // Drop from output
      }
    }

    result.push(validated);
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  buildEvidence
//  Constructs an EvidenceContext from an event batch.
//  Call this once per ingest cycle and reuse for all validateTechnique calls.
// ─────────────────────────────────────────────────────────────────────────────
function buildEvidence(events = [], detections = []) {
  return new EvidenceContext(events, detections);
}

// ─────────────────────────────────────────────────────────────────────────────
//  isRuleEligibleForTechnique
//  Pre-compilation check: returns false when a rule should NEVER produce a
//  given technique assignment (e.g. auth-EventID rules tagged as T1190).
//  Used by SigmaEngine._compileRule to strip invalid technique tags at load time.
// ─────────────────────────────────────────────────────────────────────────────
function isRuleEligibleForTechnique(rule, tid) {
  // Keyword-only rules are not eligible for any evidence-gated technique
  if (isKeywordOnlyRule(rule) && TECHNIQUE_EVIDENCE_RULES[tid]) {
    return false;
  }

  // Blocked-source rules
  const blockedSrc = TECHNIQUE_BLOCKED_SOURCES[tid];
  if (blockedSrc) {
    const det     = rule.detection || {};
    const sel     = det.selection  || {};
    const evtIds  = Array.isArray(sel.EventID) ? sel.EventID : [];
    const service = (rule.logsource?.service || '').toLowerCase();

    const allAuthIds = evtIds.length > 0 && evtIds.every(id => blockedSrc.blockedEventIds.has(String(id)));
    const blockedLS  = blockedSrc.blockedLogsources.has(service);

    if (allAuthIds || blockedLS) {
      return false;
    }
  }

  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  sanitizeRuleTags
//  Removes technique tags from a rule that would produce invalid assignments.
//  Call during rule compilation to strip bad tags before the rule is indexed.
// ─────────────────────────────────────────────────────────────────────────────
function sanitizeRuleTags(rule) {
  if (!rule || !Array.isArray(rule.tags)) return rule;

  const newTags = rule.tags.filter(tag => {
    const m = tag.toLowerCase().match(/attack\.(t\d+(?:\.\d+)?)/);
    if (!m) return true; // keep non-technique tags
    const tid = m[1].toUpperCase();
    const eligible = isRuleEligibleForTechnique(rule, tid);
    if (!eligible) {
      console.warn(`[CEA] Removed invalid tag "${tag}" from rule "${rule.id || rule.title}" — ${TECHNIQUE_EVIDENCE_RULES[tid]?.reason || TECHNIQUE_BLOCKED_SOURCES[tid]?.description || 'not eligible'}`);
    }
    return eligible;
  });

  if (newTags.length !== rule.tags.length) {
    return { ...rule, tags: newTags, _ceaSanitized: true };
  }
  return rule;
}

// ─────────────────────────────────────────────────────────────────────────────
//  FINAL GUARD — mitreMapperGuard
//  Applied at the MITRE-mapper output stage as a last-resort safety net.
//  Removes any technique that should not have survived to this point.
//
//  @param {Array}  techniques   — output of MitreMapper.mapDetection().techniques
//  @param {Object} evidenceCtx  — EvidenceContext for the current batch
//  @param {Object} [detection]  — the parent detection (for context)
//  @returns {Array}             — filtered techniques
// ─────────────────────────────────────────────────────────────────────────────
function mitreMapperGuard(techniques, evidenceCtx, detection = {}) {
  if (!Array.isArray(techniques) || techniques.length === 0) return techniques;

  const evt     = detection.event || {};
  const ruleCtx = { logsource: detection.logsource || {}, ruleId: detection.ruleId };

  return techniques.filter(t => {
    const result = validateTechnique(t.id, evidenceCtx, evt, detection, ruleCtx);
    if (!result.allowed) {
      console.warn(`[CEA/MitreGuard] Stripped technique ${t.id} from MITRE output: ${result.reason}`);
    }
    return result.allowed;
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  PUBLIC API
// ─────────────────────────────────────────────────────────────────────────────
module.exports = {
  // Core validators
  validateTechnique,
  validateDetection,
  validateBatch,

  // Evidence context
  buildEvidence,
  EvidenceContext,

  // Rule compilation helpers
  isRuleEligibleForTechnique,
  sanitizeRuleTags,
  isKeywordOnlyRule,

  // MITRE-mapper final guard
  mitreMapperGuard,

  // Audit & metrics
  getAuditLog  : ()  => [..._auditLog],
  getMetrics   : ()  => JSON.parse(JSON.stringify(_metrics)),
  resetAuditLog: ()  => { _auditLog.length = 0; },
  resetMetrics : ()  => {
    Object.keys(_metrics).forEach(k => {
      if (typeof _metrics[k] === 'number') _metrics[k] = 0;
      else if (typeof _metrics[k] === 'object') _metrics[k] = {};
    });
  },

  // Exported constants (for testing / downstream consumers)
  TECHNIQUE_EVIDENCE_RULES,
  TECHNIQUE_BLOCKED_SOURCES,
  AUTH_ONLY_EVENT_IDS,
};
