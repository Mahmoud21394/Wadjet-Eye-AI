/**
 * ══════════════════════════════════════════════════════════
 *  Sysmon Log Analyzer — Backend Routes v2.0
 *  backend/routes/sysmon.js
 *
 *  POST /api/sysmon/analyze        — Upload + parse EVTX/JSON
 *  GET  /api/sysmon/sessions       — List analysis sessions
 *  GET  /api/sysmon/sessions/:id   — Single session detail
 *  GET  /api/sysmon/sessions/:id/detections — Detection list
 *  GET  /api/sysmon/rules          — Available detection rules
 *  GET  /api/sysmon/sessions/:id/export — Export CSV/JSON
 *  DELETE /api/sysmon/sessions/:id — Delete session
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { supabase } = require('../config/supabase');
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');

/* ── Detection Rules — mapped to Sysmon Event IDs + MITRE ATT&CK ── */
const DETECTION_RULES = [
  // Process Creation (Event ID 1)
  { id:'SR-001', event_id:1, rule_name:'Suspicious PowerShell Encoded Command', pattern: /powershell.*-enc\s+[A-Za-z0-9+/=]{20,}/i, severity:'HIGH', mitre_tactic:'TA0002', mitre_technique:'T1059.001', description:'PowerShell encoded command execution — common malware delivery technique' },
  { id:'SR-002', event_id:1, rule_name:'LSASS Access via ProcDump',              pattern: /procdump.*lsass|lsass.*procdump/i,         severity:'CRITICAL', mitre_tactic:'TA0006', mitre_technique:'T1003.001', description:'Credential dumping via ProcDump targeting LSASS' },
  { id:'SR-003', event_id:1, rule_name:'Mimikatz Execution',                     pattern: /mimikatz|mimilib|sekurlsa|kerberos::list|lsadump::sam/i, severity:'CRITICAL', mitre_tactic:'TA0006', mitre_technique:'T1003', description:'Mimikatz credential extraction tool detected' },
  { id:'SR-004', event_id:1, rule_name:'WScript/CScript Executing VBScript',     pattern: /wscript|cscript.*\.(vbs|js|jse|wsf)/i,    severity:'HIGH', mitre_tactic:'TA0002', mitre_technique:'T1059.005', description:'Windows Script Host executing potential malicious script' },
  { id:'SR-005', event_id:1, rule_name:'PsExec Lateral Movement',               pattern: /psexec|psexesvc|paexec/i,                  severity:'HIGH', mitre_tactic:'TA0008', mitre_technique:'T1021.002', description:'PsExec lateral movement tool detected' },
  { id:'SR-006', event_id:1, rule_name:'Scheduled Task Persistence',            pattern: /schtasks.*\/create|at\.exe.*\/add/i,       severity:'HIGH', mitre_tactic:'TA0003', mitre_technique:'T1053.005', description:'Scheduled task creation for persistence' },
  { id:'SR-007', event_id:1, rule_name:'Shadow Copy Deletion',                  pattern: /vssadmin.*delete|wmic.*shadowcopy.*delete/i, severity:'CRITICAL', mitre_tactic:'TA0040', mitre_technique:'T1490', description:'Volume Shadow Copy deletion — ransomware indicator' },
  { id:'SR-008', event_id:1, rule_name:'Mshta Running Remote Script',           pattern: /mshta.*http[s]?:/i,                       severity:'HIGH', mitre_tactic:'TA0005', mitre_technique:'T1218.005', description:'Mshta loading remote script — LOLBin abuse' },
  { id:'SR-009', event_id:1, rule_name:'Certutil Download',                     pattern: /certutil.*-urlcache|-decode/i,             severity:'HIGH', mitre_tactic:'TA0005', mitre_technique:'T1140', description:'Certutil used to download or decode content' },
  { id:'SR-010', event_id:1, rule_name:'Regsvr32 Squiblydoo',                  pattern: /regsvr32.*\/[si].*\/u.*\.sct|regsvr32.*scrobj/i, severity:'HIGH', mitre_tactic:'TA0005', mitre_technique:'T1218.010', description:'Regsvr32 bypass via scrobj.dll (Squiblydoo)' },

  // Network Connection (Event ID 3)
  { id:'SR-011', event_id:3, rule_name:'C2 Cobalt Strike Port (443/80/8443)',    pattern: /DestinationPort.*\b(443|80|8443|4444|8080)\b/, severity:'MEDIUM', mitre_tactic:'TA0011', mitre_technique:'T1071.001', description:'Outbound connection on common C2 ports' },
  { id:'SR-012', event_id:3, rule_name:'DNS over Non-Standard Port',             pattern: /DestinationPort.*\b(5353|8053|5355)\b/,   severity:'MEDIUM', mitre_tactic:'TA0011', mitre_technique:'T1071.004', description:'DNS communication on non-standard port' },
  { id:'SR-013', event_id:3, rule_name:'WMI Remote Network Connection',         pattern: /wmiprvse\.exe.*DestinationPort/i,          severity:'HIGH', mitre_tactic:'TA0008', mitre_technique:'T1021.006', description:'WMI remote execution network activity' },

  // File Creation (Event ID 11)
  { id:'SR-014', event_id:11, rule_name:'Executable Dropped in Temp/AppData',   pattern: /\\(Temp|AppData|LocalAppData|ProgramData)\\.*\.(exe|dll|bat|ps1|vbs|js)/i, severity:'HIGH', mitre_tactic:'TA0002', mitre_technique:'T1059', description:'Executable file created in temporary user space' },
  { id:'SR-015', event_id:11, rule_name:'Office Macro Dropping Script',         pattern: /\.(doc|xls|ppt)[mx]?\\.*\.(exe|ps1|bat|vbs)/i, severity:'HIGH', mitre_tactic:'TA0001', mitre_technique:'T1566.001', description:'Office document spawning or dropping executable' },

  // Registry (Event ID 13)
  { id:'SR-016', event_id:13, rule_name:'Run Key Persistence Added',            pattern: /CurrentVersion\\Run|RunOnce|RunServices/i, severity:'HIGH', mitre_tactic:'TA0003', mitre_technique:'T1547.001', description:'Registry Run key modified for persistence' },
  { id:'SR-017', event_id:13, rule_name:'AppInit_DLLs Modification',            pattern: /AppInit_DLLs|LoadAppInit_DLLs/i,           severity:'CRITICAL', mitre_tactic:'TA0003', mitre_technique:'T1546.010', description:'AppInit_DLLs registry persistence' },
  { id:'SR-018', event_id:13, rule_name:'Debugger Hijacking (IFEO)',            pattern: /Image File Execution Options\\.*Debugger/i, severity:'CRITICAL', mitre_tactic:'TA0003', mitre_technique:'T1546.012', description:'Image File Execution Options debugger hijacking' },

  // Process Access (Event ID 10)
  { id:'SR-019', event_id:10, rule_name:'LSASS Memory Read Access',             pattern: /lsass\.exe.*GrantedAccess/i,               severity:'CRITICAL', mitre_tactic:'TA0006', mitre_technique:'T1003.001', description:'Process accessing LSASS memory — credential dumping' },
  { id:'SR-020', event_id:10, rule_name:'Process Injection via OpenProcess',    pattern: /GrantedAccess.*0x1F0FFF|0x1410|0x143A/,    severity:'HIGH', mitre_tactic:'TA0005', mitre_technique:'T1055', description:'Suspicious GrantedAccess mask indicating process injection' },
];

/* ── Sysmon Event Type Mapping ── */
const SYSMON_EVENTS = {
  1:  'ProcessCreate',      2:  'FileCreateTime',      3:  'NetworkConnect',
  4:  'SysmonStatus',       5:  'ProcessTerminate',    6:  'DriverLoad',
  7:  'ImageLoad',          8:  'CreateRemoteThread',  9:  'RawAccessRead',
  10: 'ProcessAccess',      11: 'FileCreate',          12: 'RegistryEvent',
  13: 'RegistryValue',      14: 'RegistryKey',         15: 'FileCreateStreamHash',
  16: 'SysmonConfig',       17: 'PipeEvent',           18: 'PipeConnected',
  19: 'WmiEvent',           20: 'WmiEvent',             21: 'WmiEvent',
  22: 'DNSQuery',           23: 'FileDelete',           25: 'ProcessTampering',
  26: 'FileDeleteDetected', 27: 'FileBlockExecutable', 28: 'FileBlockShredding',
  29: 'FileExecutableDetected',
};

/* ─────────────────────────────────────────────────────────
   POST /api/sysmon/analyze — Upload and parse log file
─────────────────────────────────────────────────────────── */
router.post('/analyze',
  verifyToken,
  asyncHandler(async (req, res) => {
    const { filename, content, format = 'json' } = req.body;

    if (!filename) {
      return res.status(400).json({ error: 'filename is required' });
    }

    if (!content) {
      return res.status(400).json({ error: 'content (base64 or JSON string) is required' });
    }

    // Create session record
    const { data: session, error: sessErr } = await supabase
      .from('sysmon_logs')
      .insert({
        tenant_id:   req.user.tenant_id,
        filename,
        uploaded_by: req.user.id,
        format,
        status:      'processing',
      })
      .select('id')
      .single();

    if (sessErr) throw new Error(sessErr.message);

    const sessionId = session.id;

    // Return session ID immediately — processing is async
    res.status(202).json({
      session_id: sessionId,
      message:    'Analysis started',
      status:     'processing',
    });

    // ── Background analysis ──────────────────────────────────
    setImmediate(async () => {
      try {
        const t0      = Date.now();
        let events    = [];

        // ── Parse content ──────────────────────────────────
        if (format === 'json') {
          try {
            const raw = typeof content === 'string' ? JSON.parse(content) : content;
            events = Array.isArray(raw) ? raw : (raw.events || raw.records || [raw]);
          } catch {
            events = _parseJsonLines(content);
          }
        } else if (format === 'csv') {
          events = _parseCSVSysmon(content);
        } else {
          // EVTX / XML (plain text representation)
          events = _parseXMLSysmon(content);
        }

        const totalEvents   = events.length;
        const detections    = [];
        let   highRiskCount = 0;
        const rawSample     = events.slice(0, 5);

        // ── Run detection rules against events ────────────
        for (const evt of events) {
          const evtStr    = JSON.stringify(evt).toLowerCase();
          const evtId     = parseInt(evt.EventID || evt.event_id || evt.eventId || 0);
          const cmdLine   = evt.CommandLine || evt.commandLine || evt.command_line || '';
          const targetImg = evt.TargetFilename || evt.TargetImage || evt.ImageLoaded || evt.TargetObject || '';
          const network   = `DestinationPort ${evt.DestinationPort || ''} ${evt.DestinationIp || ''}`;

          const testFields = [cmdLine, targetImg, network, evtStr].join(' ');

          for (const rule of DETECTION_RULES) {
            // Only apply rule if event ID matches (or rule is generic)
            if (rule.event_id && evtId && rule.event_id !== evtId) continue;

            if (rule.pattern.test(testFields)) {
              const det = {
                log_id:          sessionId,
                tenant_id:       req.user.tenant_id,
                event_id:        evtId || null,
                event_type:      SYSMON_EVENTS[evtId] || 'Unknown',
                severity:        rule.severity,
                rule_name:       rule.rule_name,
                rule_id:         rule.id,
                mitre_tactic:    rule.mitre_tactic,
                mitre_technique: rule.mitre_technique,
                process_name:    _extractField(evt, ['Image','ProcessName','process_name']) || null,
                process_path:    _extractField(evt, ['Image','ImageLoaded','process_path']) || null,
                command_line:    cmdLine.slice(0, 1000) || null,
                parent_process:  _extractField(evt, ['ParentImage','parent_process']) || null,
                user_name:       _extractField(evt, ['User','SubjectUserName','user_name']) || null,
                hostname:        _extractField(evt, ['Computer','Hostname','hostname']) || null,
                remote_ip:       _extractField(evt, ['DestinationIp','DestinationHostname','remote_ip']) || null,
                remote_port:     parseInt(_extractField(evt, ['DestinationPort','remote_port'])) || null,
                hash_md5:        _extractHash(evt, 'MD5'),
                hash_sha256:     _extractHash(evt, 'SHA256'),
                raw_event:       evt,
                confidence:      0.80,
              };

              detections.push(det);
              if (rule.severity === 'CRITICAL' || rule.severity === 'HIGH') highRiskCount++;
            }
          }
        }

        // ── Save detections in batches ────────────────────
        if (detections.length > 0) {
          const CHUNK = 50;
          for (let i = 0; i < detections.length; i += CHUNK) {
            const { error } = await supabase
              .from('sysmon_detections')
              .insert(detections.slice(i, i + CHUNK));
            if (error) console.warn('[Sysmon] Detection insert warning:', error.message);
          }
        }

        // ── Build summary ─────────────────────────────────
        const summary = {
          total_events:    totalEvents,
          total_detections:detections.length,
          high_risk:       highRiskCount,
          techniques:      [...new Set(detections.map(d => d.mitre_technique))],
          tactics:         [...new Set(detections.map(d => d.mitre_tactic))],
          top_rules:       _topRules(detections),
          event_types:     _countEventTypes(events),
        };

        // ── Update session ─────────────────────────────────
        await supabase.from('sysmon_logs').update({
          status:        detections.length > 0 ? 'completed' : 'completed',
          total_events:  totalEvents,
          parsed_events: totalEvents,
          detections:    detections.length,
          high_risk:     highRiskCount,
          processing_ms: Date.now() - t0,
          processed_at:  new Date().toISOString(),
          raw_sample:    rawSample,
          summary,
        }).eq('id', sessionId);

        console.info(`[Sysmon] Session ${sessionId}: ${totalEvents} events, ${detections.length} detections in ${Date.now()-t0}ms`);

        // ── Log to detection_timeline if high-risk ────────
        if (highRiskCount > 0) {
          await supabase.from('detection_timeline').insert({
            tenant_id:   req.user.tenant_id,
            event_type:  'sysmon_analysis',
            title:       `Sysmon: ${highRiskCount} high-risk detections in ${filename}`,
            description: `Analyzed ${totalEvents} events, found ${detections.length} detections (${highRiskCount} high/critical)`,
            severity:    highRiskCount > 5 ? 'HIGH' : 'MEDIUM',
            source:      'sysmon_analyzer',
            metadata:    { session_id: sessionId, filename, detections: detections.length, high_risk: highRiskCount },
          });
        }

      } catch (err) {
        console.error('[Sysmon] Analysis error:', err.message);
        await supabase.from('sysmon_logs').update({
          status:        'failed',
          error_message: err.message,
        }).eq('id', sessionId);
      }
    });
  })
);

/* ─────────────────────────────────────────────────────────
   GET /api/sysmon/sessions — List sessions
─────────────────────────────────────────────────────────── */
router.get('/sessions', verifyToken, asyncHandler(async (req, res) => {
  const { page = 1, limit = 20 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  const { data, error, count } = await supabase
    .from('sysmon_logs')
    .select('id, filename, status, total_events, detections, high_risk, uploaded_at, processed_at, summary', { count: 'exact' })
    .eq('tenant_id', req.user.tenant_id)
    .order('uploaded_at', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (error) throw new Error(error.message);
  res.json({ data: data || [], total: count || 0, page: +page, limit: +limit });
}));

/* ─────────────────────────────────────────────────────────
   GET /api/sysmon/sessions/:id — Session detail
─────────────────────────────────────────────────────────── */
router.get('/sessions/:id', verifyToken, asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('sysmon_logs')
    .select('*')
    .eq('id', req.params.id)
    .eq('tenant_id', req.user.tenant_id)
    .single();

  if (error || !data) throw createError(404, 'Session not found');
  res.json(data);
}));

/* ─────────────────────────────────────────────────────────
   GET /api/sysmon/sessions/:id/detections
─────────────────────────────────────────────────────────── */
router.get('/sessions/:id/detections', verifyToken, asyncHandler(async (req, res) => {
  const { severity, page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  let q = supabase
    .from('sysmon_detections')
    .select('*', { count: 'exact' })
    .eq('log_id', req.params.id)
    .eq('tenant_id', req.user.tenant_id)
    .order('created_at', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (severity) q = q.eq('severity', severity.toUpperCase());

  const { data, error, count } = await q;
  if (error) throw new Error(error.message);

  res.json({ data: data || [], total: count || 0, page: +page, limit: +limit });
}));

/* ─────────────────────────────────────────────────────────
   GET /api/sysmon/rules — Detection rules reference
─────────────────────────────────────────────────────────── */
router.get('/rules', asyncHandler(async (req, res) => {
  res.json({
    data:  DETECTION_RULES.map(r => ({
      id:              r.id,
      rule_name:       r.rule_name,
      event_id:        r.event_id,
      severity:        r.severity,
      mitre_tactic:    r.mitre_tactic,
      mitre_technique: r.mitre_technique,
      description:     r.description,
    })),
    total: DETECTION_RULES.length,
  });
}));

/* ─────────────────────────────────────────────────────────
   DELETE /api/sysmon/sessions/:id
─────────────────────────────────────────────────────────── */
router.delete('/sessions/:id',
  verifyToken,
  requireRole(['ANALYST', 'ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const { error } = await supabase
      .from('sysmon_logs')
      .delete()
      .eq('id', req.params.id)
      .eq('tenant_id', req.user.tenant_id);

    if (error) throw new Error(error.message);
    res.status(204).end();
  })
);

/* ════════════════════════════════════════════
   HELPERS
═════════════════════════════════════════════ */
function _extractField(evt, keys) {
  for (const k of keys) {
    if (evt[k]) return String(evt[k]).slice(0, 500);
  }
  return null;
}

function _extractHash(evt, algo) {
  const hashes = evt.Hashes || evt.hashes || '';
  const match  = String(hashes).match(new RegExp(`${algo}=([a-fA-F0-9]+)`, 'i'));
  return match ? match[1].toLowerCase() : null;
}

function _topRules(detections) {
  const counts = {};
  for (const d of detections) {
    counts[d.rule_name] = (counts[d.rule_name] || 0) + 1;
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([rule, count]) => ({ rule, count }));
}

function _countEventTypes(events) {
  const counts = {};
  for (const e of events) {
    const id  = parseInt(e.EventID || e.event_id || 0);
    const key = SYSMON_EVENTS[id] || `Event${id}`;
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

function _parseJsonLines(text) {
  return text.split('\n')
    .filter(l => l.trim().startsWith('{'))
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
}

function _parseCSVSysmon(text) {
  const lines = text.split('\n').filter(Boolean);
  if (lines.length < 2) return [];
  const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
  return lines.slice(1).map(line => {
    const vals = line.split(',');
    const evt  = {};
    headers.forEach((h, i) => { evt[h] = (vals[i] || '').replace(/^"|"$/g, '').trim(); });
    return evt;
  });
}

function _parseXMLSysmon(text) {
  // Rudimentary XML/EVTX text extraction — looks for key fields
  const events = [];
  const eventBlocks = text.split(/<Event\s/i).slice(1);

  for (const block of eventBlocks.slice(0, 10000)) {
    const evt = {};
    const fieldMatch = block.match(/<Data Name='([^']+)'>([^<]*)<\/Data>/g) || [];
    for (const field of fieldMatch) {
      const m = field.match(/<Data Name='([^']+)'>([^<]*)<\/Data>/);
      if (m) evt[m[1]] = m[2];
    }
    // Also try attribute-style
    const idMatch = block.match(/EventID[>\s](\d+)/i);
    if (idMatch) evt.EventID = parseInt(idMatch[1]);

    if (Object.keys(evt).length > 0) events.push(evt);
  }

  return events;
}

module.exports = router;
