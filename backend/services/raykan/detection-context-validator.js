/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Detection Context Validator v1.0
 *
 *  Purpose:
 *   Prevent false-positive MITRE technique assignments by enforcing
 *   strict data-source and evidence requirements before mapping.
 *
 *  Key problems solved:
 *   • T1190 (Web Attack) mapped without any HTTP/web-server log evidence
 *   • T1021 (SMB Lateral Movement) mapped on bare LogonType=3 events
 *   • Auth events correlated as lateral-movement without multi-host proof
 *   • 4625+4624+4688 sequences labeled as complex TTPs without context
 *
 *  Public API:
 *   validate(detection, eventBatch, allDetections)
 *     → { valid, suppressed, reason, adjustedTechniques, confidence }
 *   correlateAuthSequence(events)
 *     → { type, techniques, confidence, evidence }
 *   filterDetectionsByContext(detections, events)
 *     → filtered detection array with suppressed FPs removed/adjusted
 *   getMetrics()
 *     → { suppressed_count, adjusted_count, validated_count }
 *
 *  backend/services/raykan/detection-context-validator.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

// ── Telemetry / Data-source requirements per technique ────────────
// Maps MITRE technique IDs to required telemetry fields/indicators.
// A detection for that technique is ONLY valid when at least one of
// the `requiresAny` conditions is satisfied by the event context.
const TECHNIQUE_TELEMETRY_REQUIREMENTS = {

  // ── T1190 — Exploit Public-Facing Application ─────────────────
  // Requires evidence of a web server process or HTTP/web logs
  'T1190': {
    label: 'Exploit Public-Facing Application',
    requiresAny: [
      // Web server process as parent
      { field: 'parentProc',  matchAny: ['w3wp.exe', 'httpd.exe', 'nginx.exe', 'php.exe', 'apache.exe', 'tomcat.exe', 'iisexpress.exe'] },
      // HTTP log source category in the event batch context
      { contextFlag: 'has_webserver_logs' },
      // Web-related logsource
      { logsourceCategory: ['webserver', 'web', 'http', 'iis', 'apache', 'nginx'] },
      // URL or HTTP fields present
      { field: 'url',    present: true },
      { field: 'raw.cs-uri-stem',  present: true },
      { field: 'raw.cs-method',    present: true },
      { field: 'raw.c-ip',         present: true },
    ],
    suppressedAlternative: null,  // no fallback — just suppress
    falsePositiveNote: 'T1190 requires web-server telemetry (parent process or HTTP log fields)',
  },

  // ── T1021.002 — SMB/Windows Admin Shares ──────────────────────
  // Requires evidence of actual SMB/network admin share activity,
  // NOT just any network logon
  'T1021.002': {
    label: 'SMB/Windows Admin Shares Lateral Movement',
    requiresAny: [
      // PsExec or SMB-specific tooling present
      { field: 'process',  matchAny: ['psexec.exe', 'psexec64.exe'] },
      { field: 'commandLine', containsAny: ['\\\\\\\\', 'admin$', 'ipc$', 'c$', 'd$', 'psexec'] },
      // Network connection to port 445 (SMB) from a suspicious process
      { multiField: { dstPort: ['445'], process: ['psexec.exe', 'psexec64.exe', 'cmd.exe', 'powershell.exe'] } },
      // Lateral movement confirmed by multi-host evidence in batch
      { contextFlag: 'multi_host_activity' },
      // Share-specific event with Admin$ / C$ evidence
      { field: 'raw.ShareName', containsAny: ['admin$', 'ipc$', 'c$'] },
      { field: 'raw.ObjectName', containsAny: ['\\\\admin$', '\\\\c$', '\\\\ipc$'] },
    ],
    suppressedAlternative: null,
    falsePositiveNote: 'T1021.002 requires SMB/admin-share evidence, not just LogonType=3',
  },

  // ── T1021 (parent) — Remote Services ──────────────────────────
  'T1021': {
    label: 'Remote Services',
    requiresAny: [
      { field: 'process', matchAny: ['psexec.exe', 'psexec64.exe', 'winrm.cmd', 'wmic.exe', 'schtasks.exe'] },
      { contextFlag: 'multi_host_activity' },
      { field: 'dstPort', matchAny: ['445', '3389', '5985', '5986', '22'] },
    ],
    suppressedAlternative: null,
    falsePositiveNote: 'T1021 requires concrete remote service evidence',
  },

  // ── T1021.006 — WinRM ─────────────────────────────────────────
  'T1021.006': {
    label: 'Windows Remote Management',
    requiresAny: [
      { field: 'process', matchAny: ['wsmprovhost.exe', 'winrm.cmd'] },
      { field: 'parentProc', matchAny: ['wsmprovhost.exe'] },
      { field: 'dstPort', matchAny: ['5985', '5986'] },
      { field: 'raw.Channel', matchAny: ['Microsoft-Windows-WinRM/Operational'] },
    ],
    suppressedAlternative: null,
    falsePositiveNote: 'T1021.006 requires WinRM process or port 5985/5986 evidence',
  },

  // ── T1550.002 — Pass-the-Hash ─────────────────────────────────
  // LogonType=3 + NTLM alone is not enough — must have multi-host or
  // explicit PtH tooling indicators
  'T1550.002': {
    label: 'Pass-the-Hash',
    requiresAny: [
      // Classic PtH: NTLM network logon to DIFFERENT machine than source
      { contextFlag: 'cross_host_ntlm_logon' },
      // Explicit PtH tooling
      { field: 'commandLine', containsAny: ['sekurlsa::pth', '-pth', 'wce -s', 'pass.*hash', 'ntlm.*hash'] },
      // Multi-host activity required
      { contextFlag: 'multi_host_activity' },
    ],
    suppressedAlternative: 'T1078',  // Downgrade to Valid Accounts if single-host NTLM
    falsePositiveNote: 'T1550.002 (PtH) requires cross-host NTLM evidence; LogonType=3 alone is insufficient',
  },

  // ── T1110 — Brute Force ──────────────────────────────────────
  // 4625 with LogonType=3 alone triggers this; require multiple failures
  'T1110': {
    label: 'Brute Force',
    requiresAny: [
      // Multiple 4625 events in batch (≥3)
      { contextFlag: 'multiple_4625_events' },
      // Explicit brute-force tooling
      { field: 'commandLine', containsAny: ['hydra', 'medusa', 'ncrack', 'crowbar', 'spray'] },
    ],
    suppressedAlternative: 'T1078',  // Downgrade to Valid Accounts for single failures
    falsePositiveNote: 'T1110 (Brute Force) requires ≥3 failed logon events; single 4625 mapped to T1078',
  },
  'T1110.001': {
    label: 'Password Guessing',
    requiresAny: [
      { contextFlag: 'multiple_4625_events' },
    ],
    suppressedAlternative: 'T1078',
    falsePositiveNote: 'T1110.001 requires multiple failed logon events',
  },
  'T1110.003': {
    label: 'Password Spraying',
    requiresAny: [
      { contextFlag: 'multiple_target_users' },
      { contextFlag: 'multiple_4625_events' },
    ],
    suppressedAlternative: 'T1078',
    falsePositiveNote: 'T1110.003 (Password Spraying) requires multiple target usernames',
  },
};

// ── Logsource category → data source type mapping ─────────────────
const LOGSOURCE_DATASOURCE = {
  'webserver'        : 'web',
  'web'              : 'web',
  'iis'              : 'web',
  'apache'           : 'web',
  'nginx'            : 'web',
  'http'             : 'web',
  'security'         : 'windows_security',
  'system'           : 'windows_system',
  'application'      : 'windows_application',
  'process_creation' : 'process',
  'file_event'       : 'file',
  'network_connection': 'network',
  'dns'              : 'network_dns',
  'registry_event'   : 'registry',
  'powershell'       : 'powershell',
  'wmi_event'        : 'wmi',
  'sysmon'           : 'sysmon',
};

// ── Technique → correct logsource mapping ─────────────────────────
// Techniques that ONLY make sense for specific log categories.
const TECHNIQUE_REQUIRED_LOGSOURCE = {
  'T1190'    : ['webserver', 'web', 'iis', 'apache', 'nginx', 'http'],
  'T1189'    : ['webserver', 'web', 'proxy'],
  'T1071.001': ['network_connection', 'proxy', 'web', 'http', 'dns'],
  'T1071.004': ['dns', 'network_connection'],
};

// ── Context flags builder ──────────────────────────────────────────
// Derives contextual boolean flags from an event batch
function buildContextFlags(events = [], detections = []) {
  const flags = {};
  const eventArr = Array.isArray(events) ? events : [];
  const detArr   = Array.isArray(detections) ? detections : [];

  // Count event types
  const evt4625 = eventArr.filter(e => String(e.eventId || e.raw?.EventID) === '4625');
  const evt4624 = eventArr.filter(e => String(e.eventId || e.raw?.EventID) === '4624');

  flags.multiple_4625_events = evt4625.length >= 3;
  flags.has_4624_success     = evt4624.length > 0;

  // Check for web-server log evidence
  flags.has_webserver_logs = eventArr.some(e => {
    const src = (e.source || '').toLowerCase();
    const fmt = (e.format || '').toLowerCase();
    const cat = (e.raw?.logsource?.category || '').toLowerCase();
    const chan = (e.raw?.Channel || e.channel || '').toLowerCase();
    return src.includes('web') || src.includes('iis') || src.includes('apache') ||
           src.includes('nginx') || src.includes('http') ||
           fmt === 'webserver' ||
           cat === 'webserver' || cat === 'web' ||
           chan.includes('w3svc') || chan.includes('httpd') ||
           e.url != null || e.raw?.['cs-uri-stem'] != null;
  });

  // Multi-host: events from ≥2 distinct computers
  const hosts = new Set(eventArr.map(e => e.computer || e.raw?.Computer || 'unknown').filter(Boolean));
  flags.multi_host_activity = hosts.size >= 2;

  // Multiple target users (for spray detection)
  const targetUsers = new Set(
    evt4625.map(e => e.raw?.TargetUserName || e.user || '').filter(Boolean)
  );
  flags.multiple_target_users = targetUsers.size >= 3;

  // Cross-host NTLM: LogonType=3 + NTLM + source IP ≠ destination
  const ntlmLogons = evt4624.filter(e => {
    const lt = String(e.raw?.LogonType || e.logonType || '');
    const ap = (e.raw?.AuthPackage || e.raw?.AuthenticationPackageName || '').toUpperCase();
    return lt === '3' && ap === 'NTLM';
  });
  if (ntlmLogons.length > 0) {
    const computers = new Set(ntlmLogons.map(e => e.computer || e.raw?.Computer || ''));
    const srcIps    = new Set(ntlmLogons.map(e => e.srcIp || e.raw?.SourceIp || '').filter(Boolean));
    flags.cross_host_ntlm_logon = computers.size >= 2 || srcIps.size >= 2;
  } else {
    flags.cross_host_ntlm_logon = false;
  }

  return flags;
}

// ── Check a single requirement condition ──────────────────────────
// Also accepts an optional eventBatch so that field checks can search
// across all events in the ingestion batch when the detection's own
// event field is empty/missing (common when sigma rules match via field
// maps that don't round-trip into the normalized detection.event).
function checkRequirement(req, detection, event, contextFlags, eventBatch) {
  const evt = event || detection.event || {};
  const raw = evt.raw || {};

  // Context flag check
  if (req.contextFlag) {
    return !!contextFlags[req.contextFlag];
  }

  // Logsource category check
  if (req.logsourceCategory) {
    const ruleLS  = (detection.logsource?.category || '').toLowerCase();
    const evtSrc  = (evt.source || '').toLowerCase();
    const evtFmt  = (evt.format || '').toLowerCase();
    return req.logsourceCategory.some(cat =>
      ruleLS.includes(cat) || evtSrc.includes(cat) || evtFmt.includes(cat)
    );
  }

  // ── Field-based checks: first try the detection's own event, then
  //    fall back to any event in the batch that satisfies the condition.
  function checkField(e) {
    const r = e.raw || {};
    // Field presence
    if (req.present !== undefined) {
      const val = getFieldValue(req.field, e, r);
      return req.present ? val != null : val == null;
    }
    // Field matchAny (case-insensitive suffix/contains match)
    if (req.matchAny) {
      const val = String(getFieldValue(req.field, e, r) || '').toLowerCase();
      return req.matchAny.some(m => val.includes(m.toLowerCase()) || val.endsWith(m.toLowerCase()));
    }
    // Field containsAny
    if (req.containsAny) {
      const val = String(getFieldValue(req.field, e, r) || '').toLowerCase();
      return req.containsAny.some(m => val.includes(m.toLowerCase()));
    }
    // Multi-field
    if (req.multiField) {
      return Object.entries(req.multiField).every(([field, allowed]) => {
        const val = String(getFieldValue(field, e, r) || '').toLowerCase();
        return allowed.some(a => val.includes(a.toLowerCase()) || val === a.toLowerCase());
      });
    }
    return false;
  }

  // Check the detection's own event first
  if (checkField(evt)) return true;

  // Fall back to searching the event batch
  if (Array.isArray(eventBatch) && eventBatch.length > 0) {
    return eventBatch.some(e => checkField(e));
  }

  return false;
}

// ── Field value resolver (handles dot-notation + raw fallback) ────
function getFieldValue(fieldPath, evt, raw) {
  if (!fieldPath) return null;
  const parts = fieldPath.split('.');
  // Try normalized event first
  let val = evt;
  for (const p of parts) {
    if (val == null) return null;
    val = val[p];
  }
  if (val != null) return val;
  // Try raw object
  val = raw;
  for (const p of parts) {
    if (val == null) return null;
    val = val[p];
  }
  return val;
}

// ── Metrics tracker ───────────────────────────────────────────────
const _metrics = {
  suppressed_count : 0,
  adjusted_count   : 0,
  validated_count  : 0,
  fp_reasons       : {},
};

function _trackFP(reason) {
  _metrics.fp_reasons[reason] = (_metrics.fp_reasons[reason] || 0) + 1;
}

// ── Main validate() function ───────────────────────────────────────
/**
 * Validate a single detection against its supporting evidence.
 *
 * @param {Object} detection   — detection object (ruleId, tags, logsource, event, …)
 * @param {Array}  eventBatch  — all normalized events in the ingestion batch
 * @param {Array}  allDetections — all detections in the same batch (for correlation)
 * @returns {{ valid, suppressed, reason, adjustedTechniques, confidence, warnings }}
 */
function validate(detection, eventBatch = [], allDetections = []) {
  const result = {
    valid             : true,
    suppressed        : false,
    reason            : null,
    adjustedTechniques: null,
    confidence        : detection.confidence || 70,
    warnings          : [],
  };

  const tags = Array.isArray(detection.tags) ? detection.tags : [];
  const contextFlags = buildContextFlags(eventBatch, allDetections);
  const evt = detection.event || {};

  // Extract all technique IDs from tags
  const taggedTechniques = [];
  for (const tag of tags) {
    const m = tag.toLowerCase().match(/attack\.(t\d+(?:\.\d+)?)/);
    if (m) taggedTechniques.push(m[1].toUpperCase());
  }

  // ── 1. Logsource mismatch gate ────────────────────────────────
  // Reject techniques that have strict logsource requirements when
  // the ingested event does NOT come from the required source.
  // EXCEPTION: If the technique ALSO has evidence requirements that
  // would be satisfied (e.g. T1190 via web-server parentProc), the
  // evidence gate takes precedence over the logsource gate.
  const adjustedTechniques = [];
  let hadAdjustment = false;

  for (const tid of taggedTechniques) {
    const requiredLogsources = TECHNIQUE_REQUIRED_LOGSOURCE[tid];
    if (requiredLogsources && requiredLogsources.length > 0) {
      const ruleLS   = (detection.logsource?.category || '').toLowerCase();
      const evtSrc   = (evt.source || '').toLowerCase();
      const evtFmt   = (evt.format || '').toLowerCase();
      const evtChan  = (evt.channel || (evt.raw && evt.raw.Channel) || '').toLowerCase();

      const hasRequiredSource = requiredLogsources.some(ls =>
        ruleLS.includes(ls) || evtSrc.includes(ls) || evtFmt.includes(ls) || evtChan.includes(ls)
      );

      if (!hasRequiredSource) {
        // Before suppressing, check whether the evidence requirements for this
        // technique are satisfied (e.g. web-shell: parentProc IS a web server,
        // or context batch has_webserver_logs).  If evidence is satisfied we
        // let the technique survive the logsource gate.
        const evidenceReq = TECHNIQUE_TELEMETRY_REQUIREMENTS[tid];
        const evidenceSatisfied = evidenceReq
          ? evidenceReq.requiresAny.some(r => checkRequirement(r, detection, evt, contextFlags, eventBatch))
          : false;

        if (!evidenceSatisfied) {
          const msg = `[ContextValidator] ${tid} suppressed: no ${requiredLogsources.join('/')} logsource evidence`;
          result.warnings.push(msg);
          console.warn(msg);
          _trackFP(`logsource_mismatch:${tid}`);
          _metrics.suppressed_count++;
          hadAdjustment = true;
          // Don't add this technique to adjustedTechniques — it's suppressed
          continue;
        }
        // Evidence gate satisfied: technique will be evaluated in gate 2 below
      }
    }
    adjustedTechniques.push(tid);
  }

  // ── 2. Evidence requirement gate ─────────────────────────────
  const finalTechniques = [];

  for (const tid of adjustedTechniques) {
    const req = TECHNIQUE_TELEMETRY_REQUIREMENTS[tid];
    if (!req) {
      // No specific requirements — pass through
      finalTechniques.push(tid);
      continue;
    }

    // Check if ANY requirement is satisfied
    const satisfied = req.requiresAny.some(r =>
      checkRequirement(r, detection, evt, contextFlags, eventBatch)
    );

    if (!satisfied) {
      const msg = `[ContextValidator] ${tid} evidence-gated: ${req.falsePositiveNote}`;
      result.warnings.push(msg);
      console.warn(msg);
      _trackFP(`evidence_missing:${tid}`);
      hadAdjustment = true;

      if (req.suppressedAlternative) {
        // Downgrade to safer technique
        finalTechniques.push(req.suppressedAlternative);
        const adjMsg = `[ContextValidator] ${tid} → downgraded to ${req.suppressedAlternative}`;
        result.warnings.push(adjMsg);
        console.warn(adjMsg);
        _metrics.adjusted_count++;
      } else {
        _metrics.suppressed_count++;
      }
    } else {
      finalTechniques.push(tid);
    }
  }

  // Deduplicate final techniques
  const uniqueFinal = [...new Set(finalTechniques)];

  if (hadAdjustment) {
    result.adjustedTechniques = uniqueFinal;
    if (uniqueFinal.length === 0 && taggedTechniques.length > 0) {
      // All techniques were suppressed — mark detection as low-confidence
      result.confidence = Math.max(10, (detection.confidence || 70) - 30);
      result.reason = 'All tagged techniques suppressed due to insufficient telemetry evidence';
      // Don't mark as suppressed unless it was a pure web-attack with no other evidence
      if (taggedTechniques.every(t => TECHNIQUE_REQUIRED_LOGSOURCE[t])) {
        result.suppressed = true;
        result.valid = false;
      }
    } else {
      // Partial suppression — reduce confidence proportionally
      const ratio = uniqueFinal.length / Math.max(taggedTechniques.length, 1);
      result.confidence = Math.round((detection.confidence || 70) * (0.5 + 0.5 * ratio));
    }
  } else {
    _metrics.validated_count++;
  }

  return result;
}

// ── Auth Sequence Correlator ───────────────────────────────────────
/**
 * Correlates sequences of Windows auth + process events into
 * semantically correct attack patterns.
 *
 * Patterns:
 *   • Multiple 4625 → T1110 (Brute Force)
 *   • 4625 sequence → 4624 success → T1110 + T1078 (Brute + Valid Account)
 *   • Single 4625 → T1078 (Valid Accounts — failed attempt)
 *   • 4624 LogonType=3 NTLM cross-host → T1550.002 (PtH) OR T1021.002 (SMB Lateral)
 *   • 4624 LogonType=3 NTLM single-host → T1078 (Valid Accounts — network logon)
 *   • 4688 net user add after auth → T1136 (Account Creation)
 *   • 4688 cmd/powershell after 4624 → T1059 (Command & Scripting)
 *
 * @param {Array} events — normalized events
 * @returns {Array<{ type, techniques, confidence, evidence, description }>}
 */
function correlateAuthSequence(events = []) {
  const correlations = [];
  const evtArr = Array.isArray(events) ? events : [];

  // Sort by timestamp
  const sorted = [...evtArr].sort((a, b) => {
    const ta = a.timestamp instanceof Date ? a.timestamp : new Date(a.timestamp || 0);
    const tb = b.timestamp instanceof Date ? b.timestamp : new Date(b.timestamp || 0);
    return ta - tb;
  });

  // Classify events
  const failures     = sorted.filter(e => String(e.eventId || e.raw?.EventID) === '4625');
  const successes    = sorted.filter(e => String(e.eventId || e.raw?.EventID) === '4624');
  const processEvts  = sorted.filter(e => ['4688','1'].includes(String(e.eventId || e.raw?.EventID)));
  const allHosts     = new Set(sorted.map(e => e.computer || e.raw?.Computer).filter(Boolean));

  // ── Pattern 1: Brute Force (multiple failures) ────────────────
  if (failures.length >= 3) {
    const targetUsers = new Set(failures.map(e => e.raw?.TargetUserName || e.user).filter(Boolean));
    const srcIps = new Set(failures.map(e => e.srcIp || e.raw?.SourceIp).filter(Boolean));

    if (targetUsers.size >= 3) {
      // Password spraying: many users, likely one or few IPs
      correlations.push({
        type        : 'password_spray',
        techniques  : ['T1110.003', 'T1078'],
        confidence  : 85,
        evidence    : { failureCount: failures.length, targetUsers: [...targetUsers].slice(0,5), srcIps: [...srcIps] },
        description : `Password spraying: ${failures.length} failures across ${targetUsers.size} accounts`,
      });
    } else {
      // Brute force: many failures, same/few users
      correlations.push({
        type        : 'brute_force',
        techniques  : ['T1110.001', 'T1078'],
        confidence  : 80,
        evidence    : { failureCount: failures.length, targetUsers: [...targetUsers], srcIps: [...srcIps] },
        description : `Brute force: ${failures.length} failed logons against ${targetUsers.size} account(s)`,
      });
    }

    // ── Sub-pattern: Brute + Success (successful breach) ─────
    if (successes.length > 0) {
      const lastFailure = failures[failures.length - 1];
      const firstSuccess = successes[0];
      const tf = lastFailure.timestamp instanceof Date ? lastFailure.timestamp : new Date(lastFailure.timestamp || 0);
      const ts = firstSuccess.timestamp instanceof Date ? firstSuccess.timestamp : new Date(firstSuccess.timestamp || 0);
      if (ts >= tf) {
        correlations.push({
          type        : 'brute_force_success',
          techniques  : ['T1110', 'T1078'],
          confidence  : 90,
          evidence    : { failureCount: failures.length, successCount: successes.length },
          description : `Brute force succeeded: ${failures.length} failures then logon success`,
        });
      }
    }
  } else if (failures.length > 0 && failures.length < 3) {
    // Single/double failure — map to T1078 (Valid Accounts attempt), NOT T1110
    correlations.push({
      type        : 'auth_failure',
      techniques  : ['T1078'],
      confidence  : 40,
      evidence    : { failureCount: failures.length },
      description : `Auth failure(s): ${failures.length} failed logon event(s) — insufficient for brute-force classification`,
    });
  }

  // ── Pattern 2: Network Logon (4624 LogonType=3) ───────────────
  const networkLogons = successes.filter(e => {
    const lt = String(e.raw?.LogonType || e.logonType || '');
    return lt === '3';
  });

  if (networkLogons.length > 0) {
    const ntlmLogons = networkLogons.filter(e => {
      const ap = (e.raw?.AuthPackage || e.raw?.AuthenticationPackageName || '').toUpperCase();
      return ap === 'NTLM';
    });

    const srcHosts = new Set(networkLogons.map(e => e.srcIp || e.raw?.SourceIp).filter(Boolean));
    const dstHosts = new Set(networkLogons.map(e => e.computer || e.raw?.Computer).filter(Boolean));

    if (ntlmLogons.length > 0 && (srcHosts.size >= 2 || dstHosts.size >= 2 || allHosts.size >= 2)) {
      // Cross-host NTLM: genuine lateral movement indicator
      correlations.push({
        type        : 'lateral_movement_ntlm',
        techniques  : ['T1550.002', 'T1021'],
        confidence  : 75,
        evidence    : { ntlmLogonCount: ntlmLogons.length, srcHosts: [...srcHosts], dstHosts: [...dstHosts] },
        description : `Cross-host NTLM logons detected: possible Pass-the-Hash lateral movement`,
      });
    } else if (networkLogons.length > 0) {
      // Single-host network logon — just valid account usage
      correlations.push({
        type        : 'network_logon',
        techniques  : ['T1078'],
        confidence  : 50,
        evidence    : { networkLogonCount: networkLogons.length },
        description : `Network logon (LogonType=3): ${networkLogons.length} event(s) — normal network authentication, not lateral movement`,
      });
    }
  }

  // ── Pattern 3: Auth → Process execution ──────────────────────
  if (successes.length > 0 && processEvts.length > 0) {
    const netUserAdd = processEvts.filter(e => {
      const cmd = (e.commandLine || e.raw?.CommandLine || '').toLowerCase();
      return cmd.includes('net user') && (cmd.includes('/add') || cmd.includes('add'));
    });

    if (netUserAdd.length > 0) {
      correlations.push({
        type        : 'account_creation_after_auth',
        techniques  : ['T1136', 'T1136.001'],
        confidence  : 85,
        evidence    : { authSuccess: successes.length, accountCreationCmds: netUserAdd.map(e => e.commandLine || e.raw?.CommandLine) },
        description : `Account creation after authentication: ${netUserAdd.length} "net user /add" command(s) detected`,
      });
    }

    // Check for privilege escalation / persistence after auth
    const persistCmds = processEvts.filter(e => {
      const cmd = (e.commandLine || e.raw?.CommandLine || '').toLowerCase();
      return cmd.includes('schtasks') || cmd.includes('sc create') ||
             cmd.includes('reg add') || cmd.includes('new-service') ||
             cmd.includes('wmic startup');
    });

    if (persistCmds.length > 0) {
      correlations.push({
        type        : 'persistence_after_auth',
        techniques  : ['T1053', 'T1543', 'T1547'],
        confidence  : 75,
        evidence    : { authSuccess: successes.length, persistenceCmds: persistCmds.length },
        description : `Persistence mechanism established after authentication`,
      });
    }
  }

  return correlations;
}

// ── Filter Detections by Context ──────────────────────────────────
/**
 * Apply context validation to all detections in a batch.
 * Suppresses or adjusts false-positive detections in place.
 *
 * @param {Array} detections   — raw detections from SigmaEngine
 * @param {Array} eventBatch   — all normalized events in the same batch
 * @returns {Array} filtered/adjusted detections
 */
function filterDetectionsByContext(detections = [], eventBatch = []) {
  const detArr = Array.isArray(detections) ? detections : [];
  const evtArr = Array.isArray(eventBatch) ? eventBatch : [];

  const result = [];

  for (const det of detArr) {
    const validation = validate(det, evtArr, detArr);

    if (validation.suppressed) {
      // Completely suppress false-positive detection
      console.warn(
        `[ContextValidator] Suppressed detection "${det.ruleName || det.title}" ` +
        `(${det.ruleId}): ${validation.reason}`
      );
      continue;
    }

    // Apply adjustments
    const adjusted = { ...det };

    if (validation.adjustedTechniques !== null) {
      // Rebuild tags with only validated techniques
      const baseTags = (det.tags || []).filter(t => !t.toLowerCase().match(/attack\.t\d+/));
      const newTechTags = validation.adjustedTechniques.map(t => `attack.${t.toLowerCase()}`);
      adjusted.tags = [...baseTags, ...newTechTags];
      adjusted.confidence = validation.confidence;
      adjusted._contextAdjusted = true;
      adjusted._contextWarnings = validation.warnings;
    }

    if (validation.warnings.length > 0) {
      adjusted._contextWarnings = (adjusted._contextWarnings || []).concat(validation.warnings);
    }

    result.push(adjusted);
  }

  return result;
}

// ── Auth-Sequence Enhanced Detection ──────────────────────────────
/**
 * Produces context-aware detection objects for correlated auth sequences.
 * These supplement (not replace) sigma detections with higher-fidelity signals.
 *
 * @param {Array} events     — normalized events
 * @param {Array} detections — existing sigma detections
 * @returns {Array}          — supplemental detection objects
 */
function buildCorrelatedDetections(events = [], detections = []) {
  const crypto = require('crypto');
  const correlations = correlateAuthSequence(events);
  const supplemental = [];

  for (const corr of correlations) {
    // Only emit if not already covered by a sigma detection at equal/higher confidence
    const alreadyCovered = detections.some(d => {
      const dTechs = (d.tags || [])
        .map(t => { const m = t.match(/attack\.(t\d+(?:\.\d+)?)/i); return m ? m[1].toUpperCase() : null; })
        .filter(Boolean);
      return corr.techniques.some(t => dTechs.includes(t)) && (d.confidence || 70) >= corr.confidence;
    });

    if (!alreadyCovered) {
      supplemental.push({
        id           : crypto.randomUUID(),
        ruleId       : `CORR-${corr.type.toUpperCase().replace(/_/g, '-')}`,
        ruleName     : _corrTypeName(corr.type),
        description  : corr.description,
        severity     : corr.confidence >= 85 ? 'high' : corr.confidence >= 70 ? 'medium' : 'low',
        confidence   : corr.confidence,
        tags         : corr.techniques.map(t => `attack.${t.toLowerCase()}`),
        source       : 'context_correlator',
        timestamp    : new Date(),
        evidence     : corr.evidence,
        _correlated  : true,
        _corrType    : corr.type,
      });
    }
  }

  return supplemental;
}

function _corrTypeName(type) {
  const names = {
    'brute_force'              : 'Brute Force Login Sequence',
    'brute_force_success'      : 'Brute Force — Successful Compromise',
    'password_spray'           : 'Password Spraying Attack',
    'lateral_movement_ntlm'    : 'NTLM Lateral Movement (Cross-Host)',
    'network_logon'            : 'Network Authentication Event',
    'account_creation_after_auth': 'Account Creation After Authentication',
    'persistence_after_auth'   : 'Persistence Mechanism After Authentication',
    'auth_failure'             : 'Authentication Failure',
  };
  return names[type] || type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// ── Exports ────────────────────────────────────────────────────────
module.exports = {
  validate,
  correlateAuthSequence,
  filterDetectionsByContext,
  buildCorrelatedDetections,
  buildContextFlags,
  getMetrics : () => ({ ...structuredClone ? structuredClone(_metrics) : JSON.parse(JSON.stringify(_metrics)) }),
  resetMetrics: () => {
    _metrics.suppressed_count = 0;
    _metrics.adjusted_count = 0;
    _metrics.validated_count = 0;
    _metrics.fp_reasons = {};
  },
  // Exported for testing
  TECHNIQUE_TELEMETRY_REQUIREMENTS,
  TECHNIQUE_REQUIRED_LOGSOURCE,
};
