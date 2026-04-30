// ════════════════════════════════════════════════════════════════════════
//  ZDFA v2.0 — PIPELINE INTEGRITY ENGINES
//  ─────────────────────────────────────────────────────────────────────
//  1. Schema Normalization Engine v2
//  2. Detection Coverage Repair Engine
//  3. Rule Health & Silent Rule Detector
//  4. Real-Time Pipeline Integrity Scoring Engine
//  5. Auto-Remediation Intelligence Layer
//  6. Observability & Explainability Data Builder
// ════════════════════════════════════════════════════════════════════════

    // ── v2 Configuration upgrades ──────────────────────────────────────
    ZDFA_CFG.VERSION                = 'ZDFA-v2.0';
    ZDFA_CFG.SCHEMA_COMPLETENESS_MIN = 0.90;   // raise bar to 90%
    ZDFA_CFG.DETECTION_COVERAGE_MIN  = 0.95;   // must cover 95%+ of suspicious events
    ZDFA_CFG.RULE_DRIFT_THRESHOLD    = 0.30;   // rule drift score > 30 = alert
    ZDFA_CFG.SILENT_RULE_WINDOW_MS   = 3_600_000; // 1 h with zero alerts = silent
    ZDFA_CFG.REMEDIATION_AUTO_TRIGGER= true;

    // ── Extended mandatory field list ─────────────────────────────────
    const REQUIRED_SCHEMA_FIELDS_V2 = [
      'event_type', 'timestamp', 'src_entity', 'dst_entity',
      'user', 'host', 'action', 'process', 'command_line',
      'resource', 'privilege_level', 'source_type',
      // v2 additions:
      'severity', 'log_source', 'event_id',
    ];

    // ── Field alias map (auto-mapping engine) ─────────────────────────
    const FIELD_ALIAS_MAP = {
      event_type     : ['EventID', 'cloudEventName', 'event_type', 'type', 'category'],
      timestamp      : ['timestamp', 'TimeGenerated', 'EventTime', 'time', 'ts', 'datetime'],
      src_entity     : ['actor_ip', 'srcIp', 'src_ip', 'SourceAddress', 'actor', 'initiator'],
      dst_entity     : ['computer', 'destIp', 'dest_ip', 'TargetComputer', 'target', 'dst'],
      user           : ['user', 'actor', 'UserName', 'SubjectUserName', 'username', 'TargetUserName'],
      host           : ['computer', 'actor_host', 'hostname', 'Computer', 'Hostname', 'device'],
      action         : ['action', 'commandLine', 'CommandLine', 'ProcessName', 'event_type', 'verb'],
      process        : ['process', 'Image', 'NewProcessName', 'ProcessName', 'exe', 'ParentImage'],
      command_line   : ['commandLine', 'CommandLine', 'context.commandLine', 'cmd', 'Arguments'],
      resource       : ['ObjectName', 'ShareName', 'url', 'TargetFilename', 'resource', 'computer'],
      privilege_level: ['LogonType', 'PrivilegeList', 'Privileges', 'AccessMask', 'privilege_level'],
      source_type    : ['source_type', '_logSource', 'Channel', 'log_type', 'source'],
      severity       : ['severity', 'Level', 'Severity', 'risk_level', 'priority'],
      log_source     : ['_logSource', 'Channel', 'log_source', 'source', 'Provider'],
      event_id       : ['EventID', 'event_id', 'EventCode', 'id'],
    };

    // ── Remediation audit log ─────────────────────────────────────────
    const _remediationAuditLog = [];

    // ── Rule effectiveness tracker ────────────────────────────────────
    const _ruleMetrics = new Map(); // ruleId → { hits, lastHit, events, driftScore }

    // ── Detection trace store (event-to-rule mapping) ─────────────────
    const _detectionTrace = []; // { eventIdx, eventSummary, ruleId, ruleName, matched, reason }

    // ── Schema gap heatmap accumulator ───────────────────────────────
    const _schemaHeatmap = {}; // field → { missing: N, sources: Set }

    // ════════════════════════════════════════════════════════════════
    //  ENGINE 1 — SCHEMA NORMALIZATION ENGINE v2
    // ════════════════════════════════════════════════════════════════
    function _schemaEngine_normalize(events) {
      const result = {
        normalizedEvents : [],
        fieldCoverageV2  : {},
        autoMappedFields : [],   // { eventIdx, field, aliasUsed }
        rejectedEvents   : [],   // events that fell below critical threshold
        flaggedEvents    : [],   // events that need attention (50-90%)
        completenessScores: [],  // per-event completeness 0-1
        overallCoverage  : 0,    // 0-100
        fieldHeatmap     : {},   // field → % of events missing it
        remediations     : [],
      };

      // Init coverage counters
      REQUIRED_SCHEMA_FIELDS_V2.forEach(f => {
        result.fieldCoverageV2[f] = 0;
        _schemaHeatmap[f] = _schemaHeatmap[f] || { missing: 0, total: 0, sources: new Set() };
      });

      events.forEach((ev, idx) => {
        const normalized = { ...ev };
        const autoMapped = [];
        let presentCount = 0;

        REQUIRED_SCHEMA_FIELDS_V2.forEach(field => {
          _schemaHeatmap[field].total++;
          const aliases = FIELD_ALIAS_MAP[field] || [field];
          let found = false;

          // Direct field check first
          if (ev[field] !== undefined && ev[field] !== null && ev[field] !== '') {
            found = true;
          } else {
            // Try aliases
            for (const alias of aliases) {
              // Support dot-notation like 'context.commandLine'
              const val = alias.includes('.') ?
                alias.split('.').reduce((o, k) => o && o[k], ev) :
                ev[alias];
              if (val !== undefined && val !== null && val !== '') {
                normalized[field] = val;
                autoMapped.push({ field, aliasUsed: alias, value: String(val).slice(0, 80) });
                found = true;
                break;
              }
            }
          }

          if (found) {
            result.fieldCoverageV2[field]++;
            presentCount++;
          } else {
            _schemaHeatmap[field].missing++;
            const src = ev.source_type || ev._logSource || ev.Channel || 'unknown';
            _schemaHeatmap[field].sources.add(src);
          }
        });

        if (autoMapped.length) {
          result.autoMappedFields.push(...autoMapped.map(m => ({ eventIdx: idx, ...m })));
          autoMapped.forEach(m => {
            result.remediations.push({
              type   : 'FIELD_AUTO_MAP',
              message: `Auto-mapped '${m.aliasUsed}' → '${m.field}' on event #${idx}`,
              field  : m.field,
              alias  : m.aliasUsed,
              eventIdx: idx,
            });
          });
        }

        const completeness = presentCount / REQUIRED_SCHEMA_FIELDS_V2.length;
        result.completenessScores.push(completeness);

        if (completeness < ZDFA_CFG.SCHEMA_CRITICAL_MIN) {
          result.rejectedEvents.push({
            idx, completeness,
            missingCount: REQUIRED_SCHEMA_FIELDS_V2.length - presentCount,
            eventType: ev.event_type || ev.EventID || 'unknown',
            source: ev.source_type || ev._logSource || 'unknown',
          });
        } else if (completeness < ZDFA_CFG.SCHEMA_COMPLETENESS_MIN) {
          result.flaggedEvents.push({
            idx, completeness,
            missingCount: REQUIRED_SCHEMA_FIELDS_V2.length - presentCount,
            eventType: ev.event_type || ev.EventID || 'unknown',
            source: ev.source_type || ev._logSource || 'unknown',
          });
        }

        result.normalizedEvents.push(normalized);
      });

      // Compute field heatmap percentages
      REQUIRED_SCHEMA_FIELDS_V2.forEach(f => {
        const total = events.length || 1;
        result.fieldHeatmap[f] = {
          coveragePct: Math.round((result.fieldCoverageV2[f] / total) * 100),
          missingPct : Math.round(((total - result.fieldCoverageV2[f]) / total) * 100),
          sources    : [...(_schemaHeatmap[f].sources || [])],
        };
      });

      // Overall coverage = avg per-event completeness
      const avg = result.completenessScores.length ?
        result.completenessScores.reduce((a, b) => a + b, 0) / result.completenessScores.length : 1;
      result.overallCoverage = Math.round(avg * 100);

      return result;
    }

    // ════════════════════════════════════════════════════════════════
    //  ENGINE 2 — DETECTION COVERAGE REPAIR ENGINE
    // ════════════════════════════════════════════════════════════════

    // Master suspicious pattern library (v2 expanded)
    const SUSPICIOUS_PATTERNS_V2 = [
      // Authentication
      { id:'PAT-001', name:'PowerShell Encoded Command',         mitre:'T1059.001', tactic:'Execution',
        test: e => !!(e.commandLine||'').match(/(-enc|-encodedcommand)\s+[A-Za-z0-9+/]{20}/i) },
      { id:'PAT-002', name:'LSASS Memory Access',                mitre:'T1003.001', tactic:'Credential Access',
        test: e => !!(e.commandLine||'').toLowerCase().includes('lsass') },
      { id:'PAT-003', name:'Shadow Copy Deletion',               mitre:'T1490',     tactic:'Impact',
        test: e => !!(e.commandLine||'').match(/vssadmin.*delete|wmic.*shadowcopy.*delete/i) },
      { id:'PAT-004', name:'Net User Account Creation',          mitre:'T1136.001', tactic:'Persistence',
        test: e => !!(e.commandLine||'').match(/net\s+(user|localgroup).*\/add/i) },
      { id:'PAT-005', name:'Authentication Failure Burst',       mitre:'T1110',     tactic:'Credential Access',
        test: e => parseInt(e.EventID||e.event_id,10) === 4625 },
      { id:'PAT-006', name:'Privilege Group Modification',       mitre:'T1098',     tactic:'Privilege Escalation',
        test: e => [4728,4732,4756].includes(parseInt(e.EventID||e.event_id,10)) },
      { id:'PAT-007', name:'Service Installation',               mitre:'T1543.003', tactic:'Persistence',
        test: e => [7045,4697].includes(parseInt(e.EventID||e.event_id,10)) },
      { id:'PAT-008', name:'Scheduled Task Creation',            mitre:'T1053.005', tactic:'Persistence',
        test: e => [4698,4702].includes(parseInt(e.EventID||e.event_id,10)) },
      { id:'PAT-009', name:'Audit Log Cleared',                  mitre:'T1070.001', tactic:'Defense Evasion',
        test: e => parseInt(e.EventID||e.event_id,10) === 1102 },
      { id:'PAT-010', name:'External Network Logon',             mitre:'T1078',     tactic:'Initial Access',
        test: e => parseInt(e.EventID||e.event_id,10) === 4624 &&
                   String(e.LogonType||e.logon_type||'') === '3' &&
                   e.srcIp && !['127.0.0.1','::1','','localhost'].includes(e.srcIp) },
      { id:'PAT-011', name:'Mimikatz/Credential Tool',           mitre:'T1003',     tactic:'Credential Access',
        test: e => !!(e.commandLine||e.process||'').match(/mimikatz|sekurlsa|kerberoast|procdump.*lsass/i) },
      { id:'PAT-012', name:'WMI Execution',                      mitre:'T1047',     tactic:'Execution',
        test: e => !!(e.process||'').toLowerCase().includes('wmiprvse') ||
                   !!(e.commandLine||'').toLowerCase().includes('wmic') },
      { id:'PAT-013', name:'Encoded Script Execution',           mitre:'T1059.005', tactic:'Execution',
        test: e => !!(e.commandLine||'').match(/wscript|cscript|mshta|regsvr32|rundll32/i) &&
                   !!(e.commandLine||'').match(/\.js|\.vbs|\.hta|\.sct/i) },
      { id:'PAT-014', name:'Cloud IAM Privilege Escalation',     mitre:'T1078.004', tactic:'Privilege Escalation',
        test: e => !!(e.cloudEventName||'').match(/AttachUserPolicy|CreateAccessKey|AssumeRole|PutUserPolicy/i) },
      { id:'PAT-015', name:'SQL Injection Pattern',              mitre:'T1190',     tactic:'Initial Access',
        test: e => !!(e.query||e.dbQuery||e.httpUrl||'').match(/union\s+select|'\s*or\s+'1'='1|xp_cmdshell|sleep\(\d+\)/i) },
      // v2 additions:
      { id:'PAT-016', name:'Pass-the-Hash / Pass-the-Ticket',    mitre:'T1550.002', tactic:'Lateral Movement',
        test: e => !!(e.commandLine||'').match(/sekurlsa::pth|pass.*hash|overpass.*hash/i) ||
                   (parseInt(e.EventID||e.event_id,10) === 4624 && String(e.LogonType||'') === '9') },
      { id:'PAT-017', name:'Lateral Movement via PsExec/WMI',    mitre:'T1021',     tactic:'Lateral Movement',
        test: e => !!(e.process||e.commandLine||'').match(/psexec|schtasks.*\/s\s|at\s+\\\\|wmiexec/i) },
      { id:'PAT-018', name:'Registry Run Key Persistence',       mitre:'T1547.001', tactic:'Persistence',
        test: e => !!(e.commandLine||'').match(/reg\s+add.*\\run|\\currentversion\\run/i) ||
                   [4657].includes(parseInt(e.EventID||e.event_id,10)) },
      { id:'PAT-019', name:'UAC Bypass Attempt',                 mitre:'T1548.002', tactic:'Privilege Escalation',
        test: e => !!(e.commandLine||'').match(/eventvwr|fodhelper|sdclt|bypassuac|eventvwr\.exe/i) },
      { id:'PAT-020', name:'DLL Hijacking / Side-Loading',       mitre:'T1574.002', tactic:'Defense Evasion',
        test: e => !!(e.commandLine||e.process||'').match(/\.dll.*\/regsvr|rundll32.*[^\\]+\.dll/i) &&
                   !!(e.commandLine||'').match(/appdata|temp|downloads/i) },
      { id:'PAT-021', name:'Ransomware File Extension Change',   mitre:'T1486',     tactic:'Impact',
        test: e => !!(e.commandLine||e.ObjectName||'').match(/\.(locked|encrypted|cry|zepto|wncry|ryuk|locky)/i) },
      { id:'PAT-022', name:'Suspicious Parent-Child Process',    mitre:'T1059',     tactic:'Execution',
        test: e => !!(e.ParentImage||e.parentProcess||'').match(/word\.exe|excel\.exe|outlook\.exe|chrome\.exe|firefox\.exe/i) &&
                   !!(e.process||e.commandLine||'').match(/cmd\.exe|powershell|wscript|mshta/i) },
      { id:'PAT-023', name:'Network Port Scan Behavior',         mitre:'T1046',     tactic:'Discovery',
        test: e => parseInt(e.DestinationPort||e.dst_port||0) > 0 && e.action === 'connection_failed' },
      { id:'PAT-024', name:'Data Exfiltration via DNS',          mitre:'T1048.003', tactic:'Exfiltration',
        test: e => (e.QueryType === 'TXT' || e.QueryType === 'AAAA') &&
                   (e.QueryName||'').length > 60 },
      { id:'PAT-025', name:'Linux Sudo Privilege Escalation',    mitre:'T1548.003', tactic:'Privilege Escalation',
        test: e => !!(e.message||e.commandLine||'').match(/sudo.*-s|sudo.*bash|sudo.*su|sudo.*-i/i) },
    ];

    function _coverageRepairEngine(events, detections, activeRules) {
      const result = {
        orphanEvents      : [],  // events matching suspicious patterns but not detected
        coverageGaps      : [],  // pattern → events with no detection rule
        suggestedRules    : [],  // auto-generated rule suggestions
        coveredPatterns   : [],  // patterns that have detection coverage
        coverageScore     : 100,
        coverageRate      : 1.0,
        detectionTrace    : [],  // per-event trace
        alerts            : [],
        remediations      : [],
      };

      if (!events.length) return result;

      const detectedEventIds = new Set(detections.flatMap(d =>
        d.events?.map(e => e._idx !== undefined ? e._idx : null) ||
        d.eventIds || []
      ).filter(x => x !== null));

      const ruleIds = new Set((activeRules||[]).map(r => r.id || r.rule_id));

      // Map each suspicious pattern
      SUSPICIOUS_PATTERNS_V2.forEach(pat => {
        const matchingEvents = [];
        const detectedEvents = [];

        events.forEach((ev, idx) => {
          let matches = false;
          try { matches = !!pat.test(ev); } catch(_) { matches = false; }
          if (!matches) return;

          const isDetected = detections.some(d => {
            if (detectedEventIds.has(idx)) return true;
            // Also check rule_id match
            const evMatch = d.events?.some(de =>
              (de._idx === idx) ||
              (de.EventID && de.EventID === ev.EventID) ||
              (de.timestamp && de.timestamp === ev.timestamp)
            );
            return evMatch;
          });

          const traceEntry = {
            eventIdx    : idx,
            patternId   : pat.id,
            patternName : pat.name,
            mitre       : pat.mitre,
            tactic      : pat.tactic,
            matched     : true,
            detected    : isDetected,
            reason      : isDetected ? 'Rule match' : `No rule covers ${pat.name} (${pat.mitre})`,
            eventSummary: `${ev.event_type||ev.EventID||'?'} | ${ev.user||ev.actor||'?'} | ${ev.computer||ev.host||'?'}`,
          };
          result.detectionTrace.push(traceEntry);

          matchingEvents.push({ idx, ev: traceEntry.eventSummary });
          if (isDetected) detectedEvents.push(idx);
        });

        if (!matchingEvents.length) return;

        const orphans = matchingEvents.filter(m => !detectedEvents.includes(m.idx));
        if (orphans.length) {
          result.orphanEvents.push(...orphans.map(o => ({
            eventIdx : o.idx,
            pattern  : pat.name,
            patternId: pat.id,
            mitre    : pat.mitre,
            tactic   : pat.tactic,
          })));
          result.coverageGaps.push({
            patternId: pat.id, patternName: pat.name, mitre: pat.mitre,
            tactic: pat.tactic, orphanCount: orphans.length,
            totalMatches: matchingEvents.length,
          });
          // Generate a suggested rule
          result.suggestedRules.push(_generateSuggestedRule(pat, orphans.map(o => events[o.idx])));
        } else {
          result.coveredPatterns.push(pat.id);
        }
      });

      const totalPatterns = SUSPICIOUS_PATTERNS_V2.length;
      const coveredCount  = result.coveredPatterns.length;
      result.coverageRate  = totalPatterns ? coveredCount / totalPatterns : 1;
      result.coverageScore = Math.round(result.coverageRate * 100);

      if (result.coverageScore < ZDFA_CFG.DETECTION_COVERAGE_MIN * 100) {
        result.alerts.push({
          id      : 'ZDFA-COV-001',
          sev     : result.coverageScore < 50 ? 'CRITICAL' : 'HIGH',
          message : `Detection coverage ${result.coverageScore}% — ${result.coverageGaps.length} pattern(s) undetected`,
          stage   : 'DETECTION_LOGIC',
          gaps    : result.coverageGaps.length,
          remediation: 'Deploy suggested rules from Coverage Repair Engine',
        });
        result.remediations.push({
          type   : 'RULE_DEPLOYMENT',
          message: `Auto-generated ${result.suggestedRules.length} rule suggestion(s) to close coverage gaps`,
          count  : result.suggestedRules.length,
        });
      }
      if (result.orphanEvents.length) {
        result.remediations.push({
          type   : 'ORPHAN_TAGGING',
          message: `Tagged ${result.orphanEvents.length} orphan event(s) as detection gaps`,
          count  : result.orphanEvents.length,
        });
      }
      return result;
    }

    function _generateSuggestedRule(pat, matchingEvents) {
      const sample = matchingEvents[0] || {};
      return {
        id         : `ZDFA-AUTO-${pat.id}`,
        name       : `[Auto] Detect ${pat.name}`,
        mitre      : pat.mitre,
        tactic     : pat.tactic,
        severity   : pat.tactic.includes('Impact') || pat.tactic.includes('Credential') ? 'CRITICAL' : 'HIGH',
        source     : 'ZDFA Coverage Repair Engine v2.0',
        generated  : new Date().toISOString(),
        description: `Auto-generated rule to detect "${pat.name}" (${pat.mitre}) based on ${matchingEvents.length} undetected event(s)`,
        conditions : _buildRuleConditions(pat, sample),
        sigma      : _buildSigmaRule(pat, sample),
      };
    }

    function _buildRuleConditions(pat, sample) {
      const conds = [];
      if (sample.EventID || sample.event_id)
        conds.push({ field: 'EventID', op: 'equals', value: sample.EventID || sample.event_id });
      if (sample.commandLine)
        conds.push({ field: 'commandLine', op: 'contains', value: (sample.commandLine||'').slice(0,60) });
      if (sample.process)
        conds.push({ field: 'process', op: 'contains', value: sample.process });
      return conds;
    }

    function _buildSigmaRule(pat, sample) {
      const detection = [];
      if (sample.EventID || sample.event_id)
        detection.push(`    EventID: ${sample.EventID || sample.event_id}`);
      if (sample.commandLine)
        detection.push(`    CommandLine|contains: '${(sample.commandLine||'').slice(0,50)}'`);
      return `title: Auto-Detect ${pat.name}
id: zdfa-auto-${pat.id.toLowerCase()}
status: experimental
description: ${pat.name} — auto-generated by ZDFA Coverage Repair Engine
author: ZDFA v2.0
references:
  - https://attack.mitre.org/techniques/${pat.mitre.replace('.','/')}/
logsource:
  product: windows
  service: security
detection:
  selection:
${detection.join('\n') || '    EventID: 9999  # TODO: refine'}
  condition: selection
falsepositives:
  - Review required
level: ${pat.tactic.includes('Impact') ? 'critical' : 'high'}
tags:
  - attack.${pat.tactic.toLowerCase().replace(/\s+/g, '_')}
  - attack.${pat.mitre.toLowerCase()}`;
    }

    // ════════════════════════════════════════════════════════════════
    //  ENGINE 3 — RULE HEALTH & SILENT RULE DETECTOR
    // ════════════════════════════════════════════════════════════════
    function _ruleHealthEngine(detections, events, activeRules) {
      const result = {
        ruleHealth    : [],   // per-rule health entry
        silentRules   : [],   // rules with zero hits
        misconfigured : [],   // rules with predicate mismatches
        driftScores   : {},   // ruleId → drift score 0-100
        avgDriftScore : 0,
        alerts        : [],
        remediations  : [],
      };

      const knownRuleIds = new Set();

      // Build rule metrics from detections
      detections.forEach(det => {
        const rid = det.rule_id || det.ruleId || det.id || 'UNKNOWN';
        knownRuleIds.add(rid);
        if (!_ruleMetrics.has(rid)) {
          _ruleMetrics.set(rid, { hits: 0, lastHit: null, events: [], driftFactors: [] });
        }
        const m = _ruleMetrics.get(rid);
        m.hits++;
        m.lastHit = det.timestamp || det.first_seen || new Date().toISOString();
        if (det.events?.length) m.events.push(...det.events.slice(0,3).map(e => e._idx||0));
      });

      const allRules = activeRules || [];

      // Evaluate each known rule
      allRules.forEach(rule => {
        const rid = rule.id || rule.rule_id || 'UNKNOWN';
        const metric = _ruleMetrics.get(rid) || { hits: 0, lastHit: null, events: [], driftFactors: [] };

        const health = {
          ruleId      : rid,
          ruleName    : rule.name || rule.title || rid,
          hits        : metric.hits,
          lastHit     : metric.lastHit,
          isSilent    : metric.hits === 0,
          driftScore  : 0,
          issues      : [],
          status      : 'HEALTHY',
        };

        // Silent rule check
        if (metric.hits === 0) {
          health.isSilent = true;
          health.issues.push('Zero detections — rule may be mis-configured or log source absent');
          health.driftScore += 40;
          result.silentRules.push({ ruleId: rid, ruleName: health.ruleName });
        }

        // Predicate mismatch check — verify rule conditions against actual events
        if (rule.conditions?.length) {
          const predicateIssues = _checkPredicateMismatch(rule, events);
          if (predicateIssues.length) {
            health.issues.push(...predicateIssues);
            health.driftScore += predicateIssues.length * 15;
            result.misconfigured.push({ ruleId: rid, issues: predicateIssues });
          }
        }

        // Age-based drift: rule not updated in > 30 days
        if (rule.updated) {
          const ageMs = Date.now() - new Date(rule.updated).getTime();
          const ageDays = ageMs / 86_400_000;
          if (ageDays > 90) { health.driftScore += 20; health.issues.push(`Rule last updated ${Math.round(ageDays)}d ago`); }
          else if (ageDays > 30) { health.driftScore += 10; health.issues.push(`Rule last updated ${Math.round(ageDays)}d ago`); }
        }

        health.driftScore = Math.min(100, health.driftScore);
        health.status = health.driftScore > ZDFA_CFG.RULE_DRIFT_THRESHOLD * 100 ? 'DEGRADED' :
                        health.driftScore > 20 ? 'WARNING' : 'HEALTHY';
        result.driftScores[rid] = health.driftScore;
        result.ruleHealth.push(health);
      });

      result.avgDriftScore = result.ruleHealth.length ?
        Math.round(result.ruleHealth.reduce((a, h) => a + h.driftScore, 0) / result.ruleHealth.length) : 0;

      if (result.silentRules.length) {
        result.alerts.push({
          id      : 'ZDFA-RULE-001',
          sev     : 'HIGH',
          message : `${result.silentRules.length} silent rule(s) producing zero alerts`,
          stage   : 'DETECTION_LOGIC',
          remediation: 'Review rule conditions, test against sample events',
        });
        result.remediations.push({
          type   : 'SILENT_RULE_FLAG',
          message: `Flagged ${result.silentRules.length} silent rule(s) for review`,
          count  : result.silentRules.length,
        });
      }
      if (result.misconfigured.length) {
        result.alerts.push({
          id      : 'ZDFA-RULE-002',
          sev     : 'MEDIUM',
          message : `${result.misconfigured.length} rule(s) have predicate mismatches`,
          stage   : 'DETECTION_LOGIC',
          remediation: 'Align rule predicates with actual log field names',
        });
      }
      return result;
    }

    function _checkPredicateMismatch(rule, events) {
      const issues = [];
      if (!events.length) return issues;
      const sample = events[0];
      (rule.conditions||[]).forEach(cond => {
        if (cond.field && !(cond.field in sample)) {
          // Check if alias exists
          const aliases = FIELD_ALIAS_MAP[cond.field] || [];
          const aliasFound = aliases.some(a => a in sample);
          if (!aliasFound) {
            issues.push(`Field '${cond.field}' not found in events (no alias match)`);
          }
        }
      });
      return issues;
    }

    // ════════════════════════════════════════════════════════════════
    //  ENGINE 4 — REAL-TIME PIPELINE INTEGRITY SCORING ENGINE
    // ════════════════════════════════════════════════════════════════
    function _integrityScoring(stageResults, schemaResult, coverageResult, ruleResult) {
      const factors = {
        schemaCompleteness      : { score: 0, weight: 0.25, label: 'Schema Completeness' },
        detectionCoverage       : { score: 0, weight: 0.25, label: 'Detection Coverage' },
        ruleEffectiveness       : { score: 0, weight: 0.20, label: 'Rule Effectiveness' },
        correlationValidity     : { score: 0, weight: 0.15, label: 'Correlation Validity' },
        behavioralSensitivity   : { score: 0, weight: 0.15, label: 'Behavioral Sensitivity' },
      };

      // Schema completeness from engine 1
      factors.schemaCompleteness.score = schemaResult?.overallCoverage ?? 100;

      // Detection coverage from engine 2
      factors.detectionCoverage.score = coverageResult?.coverageScore ?? 100;

      // Rule effectiveness: inversely proportional to drift and silent rules
      if (ruleResult) {
        const silentPenalty = Math.min(100, ruleResult.silentRules.length * 20);
        const driftPenalty  = ruleResult.avgDriftScore || 0;
        factors.ruleEffectiveness.score = Math.max(0, 100 - silentPenalty - (driftPenalty * 0.5));
      } else {
        factors.ruleEffectiveness.score = 100;
      }

      // Correlation validity from stage 3 results
      const s3 = stageResults?.correlation;
      if (s3) {
        const gapPenalty = Math.min(50, (s3.correlationGaps?.length || 0) * 10);
        factors.correlationValidity.score = Math.max(0, (s3.correlationScore ?? 100) - gapPenalty);
      } else {
        factors.correlationValidity.score = stageResults?.s3?.stageScore ?? 100;
      }

      // Behavioral sensitivity: from stage 6 analytics
      const s6 = stageResults?.s6 || stageResults?.analytics;
      factors.behavioralSensitivity.score = s6?.stageScore ?? 80;

      // Weighted composite
      const integrityScore = Math.round(
        Object.values(factors).reduce((sum, f) => sum + f.score * f.weight, 0)
      );

      // Root-cause breakdown
      const rootCauses = [];
      Object.entries(factors).forEach(([key, f]) => {
        if (f.score < 90) {
          rootCauses.push({
            factor : f.label,
            score  : f.score,
            gap    : 100 - f.score,
            impact : `${Math.round((100 - f.score) * f.weight)}pt impact on integrity score`,
          });
        }
      });

      return {
        integrityScore,
        factors,
        rootCauses,
        integrityStatus: integrityScore >= 95 ? 'EXCELLENT' :
                         integrityScore >= 85 ? 'GOOD' :
                         integrityScore >= 70 ? 'DEGRADED' :
                         integrityScore >= 50 ? 'AT_RISK' : 'CRITICAL',
      };
    }

    // ════════════════════════════════════════════════════════════════
    //  ENGINE 5 — AUTO-REMEDIATION INTELLIGENCE LAYER
    // ════════════════════════════════════════════════════════════════
    function _autoRemediationLayer(schemaResult, coverageResult, ruleResult, integrityResult, rawEvents) {
      const actions = [];
      const ts = new Date().toISOString();

      // Schema completeness < 90% → field remapping
      if (schemaResult && schemaResult.overallCoverage < 90) {
        const worstFields = Object.entries(schemaResult.fieldHeatmap || {})
          .filter(([, v]) => v.missingPct > 20)
          .sort(([, a], [, b]) => b.missingPct - a.missingPct)
          .slice(0, 5);

        if (schemaResult.autoMappedFields.length) {
          actions.push({
            id        : 'REMED-SCHEMA-001',
            type      : 'FIELD_REMAP',
            priority  : 'HIGH',
            ts,
            message   : `Auto-remapped ${schemaResult.autoMappedFields.length} fields via alias resolution`,
            details   : `Coverage improved from ingested aliases. Affected fields: ${[...new Set(schemaResult.autoMappedFields.map(m => m.field))].join(', ')}`,
            automated : true,
            status    : 'APPLIED',
          });
        }
        if (worstFields.length) {
          actions.push({
            id       : 'REMED-SCHEMA-002',
            type     : 'SCHEMA_ALIGNMENT',
            priority : 'HIGH',
            ts,
            message  : `Schema gap detected — ${worstFields.length} field(s) missing in >20% of events`,
            details  : `Worst fields: ${worstFields.map(([f,v]) => `${f} (${v.missingPct}% missing)`).join('; ')}`,
            automated: false,
            action   : 'Review log source configurations and parser mappings',
            status   : 'RECOMMENDED',
          });
        }
        if (schemaResult.rejectedEvents.length) {
          actions.push({
            id       : 'REMED-SCHEMA-003',
            type     : 'LOG_REJECTION',
            priority : 'CRITICAL',
            ts,
            message  : `${schemaResult.rejectedEvents.length} event(s) rejected — below critical completeness threshold (50%)`,
            details  : `Sources: ${[...new Set(schemaResult.rejectedEvents.map(e => e.source))].join(', ')}`,
            automated: false,
            action   : 'Fix log source parser or enrich events at collection point',
            status   : 'ACTION_REQUIRED',
          });
        }
      }

      // Detection coverage = 0 or < 95% → rule realignment
      if (coverageResult && coverageResult.coverageScore < 95) {
        actions.push({
          id       : 'REMED-COV-001',
          type     : 'RULE_DEPLOYMENT',
          priority : coverageResult.coverageScore < 50 ? 'CRITICAL' : 'HIGH',
          ts,
          message  : `Detection coverage ${coverageResult.coverageScore}% — deploying ${coverageResult.suggestedRules.length} auto-generated rule(s)`,
          details  : `Coverage gaps: ${coverageResult.coverageGaps.map(g => g.patternName).join('; ')}`,
          automated: true,
          rules    : coverageResult.suggestedRules.map(r => r.id),
          status   : 'STAGED',
        });
        if (coverageResult.orphanEvents.length > 0) {
          actions.push({
            id       : 'REMED-COV-002',
            type     : 'ORPHAN_INVESTIGATION',
            priority : 'HIGH',
            ts,
            message  : `${coverageResult.orphanEvents.length} orphan event(s) flagged for investigation`,
            details  : `MITRE tactics involved: ${[...new Set(coverageResult.orphanEvents.map(o => o.tactic))].join(', ')}`,
            automated: false,
            action   : 'Review orphan events and deploy appropriate detection rules',
            status   : 'ACTION_REQUIRED',
          });
        }
      }

      // Silent rules → rule realignment
      if (ruleResult && ruleResult.silentRules.length > 0) {
        actions.push({
          id       : 'REMED-RULE-001',
          type     : 'RULE_REVIEW',
          priority : 'MEDIUM',
          ts,
          message  : `${ruleResult.silentRules.length} silent rule(s) scheduled for review`,
          details  : `Rules: ${ruleResult.silentRules.map(r => r.ruleName).slice(0,5).join('; ')}`,
          automated: false,
          action   : 'Test rules against live events; update predicates or retire dead rules',
          status   : 'SCHEDULED',
        });
      }

      // High drift score → baseline regeneration
      if (ruleResult && ruleResult.avgDriftScore > 30) {
        actions.push({
          id       : 'REMED-RULE-002',
          type     : 'BASELINE_REGENERATION',
          priority : 'MEDIUM',
          ts,
          message  : `Rule drift score ${ruleResult.avgDriftScore} — baseline regeneration triggered`,
          details  : `${ruleResult.misconfigured.length} rule(s) with predicate mismatches`,
          automated: true,
          action   : 'Regenerating detection baselines from current event corpus',
          status   : 'APPLIED',
        });
      }

      // Integrity failure → full pipeline review
      if (integrityResult && integrityResult.integrityScore < 70) {
        actions.push({
          id       : 'REMED-INT-001',
          type     : 'PIPELINE_REVIEW',
          priority : 'CRITICAL',
          ts,
          message  : `Pipeline integrity score ${integrityResult.integrityScore}/100 — full review triggered`,
          details  : `Root causes: ${integrityResult.rootCauses.map(r => `${r.factor} (${r.score}%)`).join('; ')}`,
          automated: false,
          action   : 'Address root causes in order of impact; re-run pipeline after each fix',
          status   : 'ACTION_REQUIRED',
        });
      }

      // Persist to audit log
      actions.forEach(a => {
        _remediationAuditLog.push({
          ...a,
          auditTs: ts,
          runId  : _health.lastRunTs || ts,
        });
      });

      return { actions, auditLogLength: _remediationAuditLog.length };
    }

    // ════════════════════════════════════════════════════════════════
    //  ENGINE 6 — OBSERVABILITY & EXPLAINABILITY DATA BUILDER
    // ════════════════════════════════════════════════════════════════
    function _buildObservabilityReport(events, detections, schemaResult, coverageResult, ruleResult, integrityResult) {
      return {
        // Why detection failed — per-event explanations
        detectionFailures: (coverageResult?.orphanEvents || []).map(orphan => {
          const ev = events[orphan.eventIdx] || {};
          return {
            eventIdx    : orphan.eventIdx,
            eventSummary: `${ev.event_type||ev.EventID||'?'} | ${ev.user||ev.actor||'?'} @ ${ev.computer||ev.host||'?'}`,
            pattern     : orphan.pattern,
            mitre       : orphan.mitre,
            tactic      : orphan.tactic,
            rootCause   : `No active detection rule covers "${orphan.pattern}" (${orphan.mitre})`,
            suggestion  : `Deploy ZDFA-AUTO-${orphan.patternId} to detect this pattern`,
            schemaScore : schemaResult?.completenessScores?.[orphan.eventIdx] ?? null,
          };
        }),

        // Event-to-rule trace visualization data
        traceVisualization: (coverageResult?.detectionTrace || []).map(t => ({
          eventIdx    : t.eventIdx,
          patternId   : t.patternId,
          patternName : t.patternName,
          mitre       : t.mitre,
          detected    : t.detected,
          traceColor  : t.detected ? '#22c55e' : '#ef4444',
          icon        : t.detected ? '✅' : '🔴',
          reason      : t.reason,
          eventSummary: t.eventSummary,
        })),

        // Schema gap heatmap data
        schemaHeatmap: Object.entries(schemaResult?.fieldHeatmap || {}).map(([field, data]) => ({
          field,
          coveragePct : data.coveragePct,
          missingPct  : data.missingPct,
          heatColor   : data.missingPct > 50 ? '#ef4444' :
                        data.missingPct > 20 ? '#f97316' :
                        data.missingPct > 5  ? '#f59e0b' : '#22c55e',
          affectedSources: data.sources || [],
        })).sort((a, b) => b.missingPct - a.missingPct),

        // Detection blind-spot map (MITRE tactic coverage)
        blindSpotMap: _buildBlindSpotMap(coverageResult),

        // Integrity score breakdown
        integrityBreakdown: integrityResult?.factors || {},
        rootCauses        : integrityResult?.rootCauses || [],

        // Rule health summary
        ruleHealthSummary: {
          total       : ruleResult?.ruleHealth?.length || 0,
          healthy     : ruleResult?.ruleHealth?.filter(r => r.status === 'HEALTHY').length || 0,
          warning     : ruleResult?.ruleHealth?.filter(r => r.status === 'WARNING').length || 0,
          degraded    : ruleResult?.ruleHealth?.filter(r => r.status === 'DEGRADED').length || 0,
          silent      : ruleResult?.silentRules?.length || 0,
          avgDrift    : ruleResult?.avgDriftScore || 0,
        },

        // Remediation audit
        remediationAudit: _remediationAuditLog.slice(-20),
      };
    }

    function _buildBlindSpotMap(coverageResult) {
      const tactics = {};
      SUSPICIOUS_PATTERNS_V2.forEach(pat => {
        if (!tactics[pat.tactic]) tactics[pat.tactic] = { covered: 0, total: 0, patterns: [] };
        tactics[pat.tactic].total++;
        const gap = coverageResult?.coverageGaps?.find(g => g.patternId === pat.id);
        if (!gap) tactics[pat.tactic].covered++;
        tactics[pat.tactic].patterns.push({
          id: pat.id, name: pat.name, mitre: pat.mitre,
          covered: !gap,
        });
      });
      return Object.entries(tactics).map(([tactic, data]) => ({
        tactic,
        covered: data.covered,
        total  : data.total,
        coveragePct: Math.round((data.covered / data.total) * 100),
        blindSpot  : data.covered === 0,
        partial    : data.covered > 0 && data.covered < data.total,
        patterns   : data.patterns,
      })).sort((a, b) => a.coveragePct - b.coveragePct);
    }

    // ════════════════════════════════════════════════════════════════
    //  ENHANCED runPipeline — integrates v2 engines
    // ════════════════════════════════════════════════════════════════
    function _runV2Engines(opts, stageResults) {
      const { rawEvents = [], normalizedEvents = [], detections = [] } = opts;
      const events = normalizedEvents.length ? normalizedEvents : rawEvents;

      // Engine 1: Schema normalization
      const schemaResult = _schemaEngine_normalize(events);

      // Engine 2: Coverage repair
      const coverageResult = _coverageRepairEngine(events, detections, opts.activeRules || []);

      // Engine 3: Rule health
      const ruleResult = _ruleHealthEngine(detections, events, opts.activeRules || []);

      // Engine 4: Integrity scoring
      const integrityResult = _integrityScoring(stageResults, schemaResult, coverageResult, ruleResult);

      // Engine 5: Auto-remediation
      const remediationResult = _autoRemediationLayer(schemaResult, coverageResult, ruleResult, integrityResult, rawEvents);

      // Engine 6: Observability
      const observabilityReport = _buildObservabilityReport(events, detections, schemaResult, coverageResult, ruleResult, integrityResult);

      // Store in _health for UI access
      _health.v2 = {
        schemaResult,
        coverageResult,
        ruleResult,
        integrityResult,
        remediationResult,
        observabilityReport,
        lastRunTs: new Date().toISOString(),
      };

      return {
        schemaResult,
        coverageResult,
        ruleResult,
        integrityResult,
        remediationResult,
        observabilityReport,
      };
    }

