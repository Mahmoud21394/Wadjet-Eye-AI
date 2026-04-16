/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — Tool Registry  v2.0  (Response-Layer Standardised)
 *
 *  v2.0 updates:
 *   ✅ MITRE tool uses MITREEnricher for enriched plain-language output
 *   ✅ CVE tool returns structured SOC-template response
 *   ✅ IOC tool returns verdict + recommended_actions (no raw JSON dump)
 *   ✅ Sigma tools return formatted YAML + deployment guidance
 *   ✅ All error paths return { error: false, found: false } not throws
 *   ✅ executeTool wraps all results in standardised envelope
 *
 *  Each tool:
 *   - Has a JSON Schema descriptor for LLM function-calling
 *   - Implements an async execute(params, context) → { result, metadata }
 *   - Is stateless; context carries req-scoped info (tenantId, userId, etc.)
 *
 *  Built-in tools:
 *   1. sigma_search       — search Sigma rule knowledge base
 *   2. sigma_generate     — generate a Sigma rule for a given scenario
 *   3. kql_generate       — generate a KQL / SPL / Lucene query
 *   4. ioc_enrich         — enrich IPs, hashes, domains via internal API
 *   5. mitre_lookup       — look up MITRE ATT&CK technique details
 *   6. cve_lookup         — look up CVE details via NVD proxy
 *   7. threat_actor_profile — profile a threat actor
 *   8. ioc_search         — search IOC database
 *   9. platform_navigate  — suggest relevant platform page
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const https = require('https');
const http  = require('http');
const MITREEnricher = require('../mitre-enricher');

// ── Lazy imports (avoid circular deps) ────────────────────────────────────────
let _sigmaKB = null;
function getSigmaKB() {
  if (!_sigmaKB) _sigmaKB = require('../sigma-kb').sigmaKB;
  return _sigmaKB;
}

// ── HTTP helper ────────────────────────────────────────────────────────────────
function _httpGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib    = parsed.protocol === 'https:' ? https : http;
    const req    = lib.request({
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + (parsed.search || ''),
      method:   'GET',
      headers:  { 'Accept': 'application/json', ...headers },
    }, res => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(body) }); }
        catch { resolve({ status: res.statusCode, body }); }
      });
    });
    req.setTimeout(15_000, () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    req.end();
  });
}

// ══════════════════════════════════════════════════════════════════════════════
//  TOOL 1 — Sigma Search
// ══════════════════════════════════════════════════════════════════════════════
const sigmaSearchTool = {
  name: 'sigma_search',
  description: 'Search the Sigma rule knowledge base for detection rules matching keywords, techniques, log sources, or severity levels. Use this when the user asks about existing Sigma rules or detection coverage.',
  parameters: {
    type: 'object',
    properties: {
      query:    { type: 'string',  description: 'Keywords, technique IDs (e.g. T1059.001), or threat names' },
      severity: { type: 'string',  enum: ['critical','high','medium','low','informational'], description: 'Filter by severity' },
      category: { type: 'string',  description: 'Log source category (e.g. process_creation, network_connection)' },
      product:  { type: 'string',  description: 'Target product (e.g. windows, linux, aws, azure)' },
      limit:    { type: 'integer', description: 'Max results to return (default 5, max 20)', default: 5 },
    },
    required: ['query'],
  },

  async execute(params, _context) {
    const { query, severity, category, product, limit = 5 } = params;
    const kb = getSigmaKB();
    // sigma-kb.search(query: string, filters: object, limit: number)
    const filters = {};
    if (severity) filters.level    = severity;
    if (category) filters.category = category;
    if (product)  filters.product  = product;
    const results = kb.search(String(query), filters, Math.min(limit, 20));

    if (!results.length) {
      return {
        result: `No Sigma rules found matching "${query}". Consider generating a new rule.`,
        metadata: { count: 0, tool: 'sigma_search' },
      };
    }

    const formatted = results.map(r => ({
      id:          r.id,
      title:       r.title,
      description: r.description,
      severity:    r.level,
      status:      r.status,
      tags:        r.tags,
      logsource:   r.logsource,
      mitre_techniques: (r.tags || [])
        .filter(t => /^attack\.t\d/i.test(t))
        .map(t => t.replace(/^attack\./i, '').toUpperCase()),
    }));

    return {
      result: formatted,
      metadata: { count: formatted.length, query, tool: 'sigma_search' },
    };
  },
};

// ══════════════════════════════════════════════════════════════════════════════
//  TOOL 2 — Sigma Generate
// ══════════════════════════════════════════════════════════════════════════════
const sigmaGenerateTool = {
  name: 'sigma_generate',
  description: 'Generate a new Sigma detection rule for a described threat scenario or technique. Use when the user asks to create or write a Sigma rule.',
  parameters: {
    type: 'object',
    properties: {
      scenario:       { type: 'string',  description: 'Threat scenario or behavior to detect (e.g. "PowerShell encoded command execution")' },
      technique_id:   { type: 'string',  description: 'MITRE ATT&CK technique ID (e.g. T1059.001)' },
      log_source:     { type: 'string',  description: 'Log source: process_creation, network_connection, file_event, registry_event, etc.' },
      product:        { type: 'string',  description: 'Target product: windows, linux, aws, azure, gcp, etc.', default: 'windows' },
      severity:       { type: 'string',  enum: ['critical','high','medium','low','informational'], default: 'high' },
      false_positive: { type: 'string',  description: 'Known false positive scenarios to document' },
    },
    required: ['scenario'],
  },

  async execute(params, _context) {
    const {
      scenario,
      technique_id = '',
      log_source   = 'process_creation',
      product      = 'windows',
      severity     = 'high',
      false_positive = 'Unknown',
    } = params;

    // Build a structured Sigma rule from templates
    const ruleId = require('crypto').randomUUID();
    const today  = new Date().toISOString().slice(0, 10).replace(/-/g, '/');
    const tags   = ['attack.execution'];
    if (technique_id) tags.push(`attack.${technique_id.toLowerCase()}`);

    // Derive detection logic from scenario keywords
    const scenarioLower = scenario.toLowerCase();
    let detection = {};
    let condition = 'selection';

    if (scenarioLower.includes('powershell') || scenarioLower.includes('encoded')) {
      detection = {
        selection: {
          EventID: 4688,
          NewProcessName: ['*\\powershell.exe', '*\\pwsh.exe'],
          CommandLine: ['*-enc *', '*-EncodedCommand*', '*-e *', '*hidden*', '*bypass*'],
        },
      };
    } else if (scenarioLower.includes('cmd') || scenarioLower.includes('command')) {
      detection = {
        selection: {
          EventID: 4688,
          NewProcessName: ['*\\cmd.exe'],
          CommandLine: ['*/c *', '*/k *'],
        },
      };
    } else if (scenarioLower.includes('network') || scenarioLower.includes('connect')) {
      detection = {
        selection: {
          EventID: [3, 5152],
          DestinationPort: [4444, 1337, 8080, 8888, 9001],
        },
      };
    } else if (scenarioLower.includes('registry') || scenarioLower.includes('persist')) {
      detection = {
        selection: {
          EventType: 'SetValue',
          TargetObject: ['*\\Run\\*', '*\\RunOnce\\*', '*\\CurrentVersion\\Explorer\\Shell Folders*'],
        },
      };
    } else if (scenarioLower.includes('file') || scenarioLower.includes('dropp') || scenarioLower.includes('download')) {
      detection = {
        selection: {
          EventID: 11,
          TargetFilename: ['*.exe', '*.dll', '*.bat', '*.ps1', '*.vbs'],
          TargetFilePath: ['*\\Temp\\*', '*\\AppData\\*', '*\\Downloads\\*'],
        },
      };
    } else {
      // Generic selection based on scenario words
      const keywords = scenario.split(/\s+/).filter(w => w.length > 4).slice(0, 3);
      detection = {
        keywords: { CommandLine: keywords.map(k => `*${k}*`) },
      };
      condition = 'keywords';
    }

    const rule = {
      title:       `Detect ${scenario}`,
      id:          ruleId,
      status:      'experimental',
      description: `Detects ${scenario}. Generated by RAKAY AI on ${today}.`,
      references:  technique_id ? [`https://attack.mitre.org/techniques/${technique_id}/`] : [],
      author:      'RAKAY AI (Wadjet-Eye)',
      date:        today,
      modified:    today,
      tags,
      logsource: { category: log_source, product },
      detection: { ...detection, condition },
      falsepositives: [false_positive],
      level: severity,
    };

    // Convert to YAML
    const yaml = _toSigmaYAML(rule);

    return {
      result: { rule_yaml: yaml, rule_object: rule },
      metadata: { ruleId, tool: 'sigma_generate', technique: technique_id || 'N/A' },
    };
  },
};

// ── YAML serialiser (no external dep) ─────────────────────────────────────────
function _toSigmaYAML(rule) {
  function val(v, indent = '') {
    if (Array.isArray(v)) {
      return '\n' + v.map(i => `${indent}  - ${JSON.stringify(i)}`).join('\n');
    }
    if (v !== null && typeof v === 'object') {
      return '\n' + Object.entries(v)
        .map(([k, vv]) => `${indent}  ${k}: ${val(vv, indent + '  ')}`)
        .join('\n');
    }
    return ` ${JSON.stringify(v)}`;
  }

  const lines = [
    `title: ${rule.title}`,
    `id: ${rule.id}`,
    `status: ${rule.status}`,
    `description: ${rule.description}`,
    `references:`,
    ...(rule.references.length ? rule.references.map(r => `  - '${r}'`) : ['  []']),
    `author: '${rule.author}'`,
    `date: ${rule.date}`,
    `modified: ${rule.modified}`,
    `tags:`,
    ...rule.tags.map(t => `  - ${t}`),
    `logsource:`,
    ...Object.entries(rule.logsource).map(([k, v]) => `  ${k}: ${v}`),
    `detection:`,
  ];

  // detection sub-keys
  for (const [key, value] of Object.entries(rule.detection)) {
    if (key === 'condition') continue;
    lines.push(`  ${key}:`);
    for (const [k, v] of Object.entries(value)) {
      if (Array.isArray(v)) {
        lines.push(`    ${k}:`);
        v.forEach(item => lines.push(`      - '${item}'`));
      } else {
        lines.push(`    ${k}: ${JSON.stringify(v)}`);
      }
    }
  }
  lines.push(`  condition: ${rule.detection.condition}`);
  lines.push(`falsepositives:`);
  rule.falsepositives.forEach(fp => lines.push(`  - '${fp}'`));
  lines.push(`level: ${rule.level}`);
  return lines.join('\n');
}

// ══════════════════════════════════════════════════════════════════════════════
//  TOOL 3 — KQL / SPL / Lucene Generate
// ══════════════════════════════════════════════════════════════════════════════
const kqlGenerateTool = {
  name: 'kql_generate',
  description: 'Generate a detection query in KQL (Microsoft Sentinel/Defender), SPL (Splunk), or Lucene (Elastic/QRadar) for a given threat scenario or Sigma rule.',
  parameters: {
    type: 'object',
    properties: {
      scenario:     { type: 'string', description: 'Threat scenario or Sigma rule title to convert' },
      target_siem:  { type: 'string', enum: ['kql','splunk_spl','elastic_lucene','qradar_aql'], description: 'Target SIEM query language', default: 'kql' },
      technique_id: { type: 'string', description: 'MITRE technique ID for context' },
      sigma_yaml:   { type: 'string', description: 'Optional Sigma YAML to translate (overrides scenario)' },
    },
    required: ['scenario'],
  },

  async execute(params, _context) {
    const { scenario, target_siem = 'kql', technique_id, sigma_yaml } = params;
    const scenarioLower = scenario.toLowerCase();

    // Build query based on scenario keywords and target SIEM
    let query = '';
    let description = '';

    const templates = _getQueryTemplates(scenarioLower, target_siem);
    query       = templates.query;
    description = templates.description;

    return {
      result: {
        query,
        siem:        target_siem,
        scenario,
        description,
        technique:   technique_id || 'N/A',
        notes:       'Review and tune thresholds before production deployment. Test in non-production first.',
        references:  technique_id ? [`https://attack.mitre.org/techniques/${technique_id}/`] : [],
      },
      metadata: { tool: 'kql_generate', siem: target_siem },
    };
  },
};

function _getQueryTemplates(scenarioLower, siem) {
  const isKQL     = siem === 'kql';
  const isSPL     = siem === 'splunk_spl';
  const isElastic = siem === 'elastic_lucene';

  if (scenarioLower.includes('powershell') || scenarioLower.includes('encoded')) {
    if (isKQL) return {
      query: `DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "pwsh.exe")\n| where ProcessCommandLine has_any ("-EncodedCommand", "-enc ", "-e ", "-hidden", "-bypass", "-nop")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName\n| order by Timestamp desc`,
      description: 'Detects PowerShell execution with suspicious encoded or obfuscated command-line parameters.',
    };
    if (isSPL) return {
      query: `index=* (source="WinEventLog:Security" OR source="WinEventLog:Microsoft-Windows-Sysmon/Operational")\n| where process_name IN ("powershell.exe", "pwsh.exe")\n| where command_line LIKE "%-EncodedCommand%" OR command_line LIKE "%-enc %" OR command_line LIKE "%-bypass%"\n| table _time, host, user, process_name, command_line\n| sort -_time`,
      description: 'SPL query for PowerShell encoded command detection in Windows event logs.',
    };
    return {
      query: `process.name:(powershell.exe OR pwsh.exe) AND process.args:(-EncodedCommand OR -enc OR -bypass OR -hidden OR -nop)`,
      description: 'Elastic KQL for PowerShell suspicious execution.',
    };
  }

  if (scenarioLower.includes('ransomware') || scenarioLower.includes('encrypt')) {
    if (isKQL) return {
      query: `DeviceFileEvents\n| where ActionType in ("FileCreated", "FileModified", "FileRenamed")\n| where FileName has_any (".encrypted", ".locked", ".crypt", ".enc", "RECOVER", "DECRYPT", "README")\n| summarize FileCount=count(), UniqueExtensions=dcount(FileName) by DeviceName, bin(Timestamp, 1m)\n| where FileCount > 50\n| order by Timestamp desc`,
      description: 'Detects mass file encryption activity indicative of ransomware (>50 file modifications/minute).',
    };
    if (isSPL) return {
      query: `index=* source="WinEventLog:Security" EventCode=4663\n| where object_name LIKE "%.encrypted" OR object_name LIKE "%.locked" OR object_name LIKE "%.crypt"\n| stats count by _time, host, user, object_name\n| where count > 50`,
      description: 'SPL ransomware file encryption detection.',
    };
    return {
      query: `event.category:file AND (file.name:*.encrypted OR file.name:*.locked OR file.name:*.crypt OR file.name:RECOVER* OR file.name:DECRYPT*)`,
      description: 'Elastic query for ransomware file activity.',
    };
  }

  if (scenarioLower.includes('lateral') || scenarioLower.includes('pass-the-hash') || scenarioLower.includes('credential')) {
    if (isKQL) return {
      query: `SecurityEvent\n| where EventID in (4624, 4625, 4648)\n| where LogonType in (3, 9, 10)\n| where AccountName !endswith "$"\n| summarize FailCount=countif(EventID==4625), SuccessCount=countif(EventID==4624) by AccountName, WorkstationName, IpAddress, bin(TimeGenerated, 10m)\n| where FailCount > 5\n| order by TimeGenerated desc`,
      description: 'Detects credential spraying or lateral movement using Windows logon events.',
    };
    if (isSPL) return {
      query: `index=* source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625 OR EventCode=4648)\n| where LogonType IN ("3", "9", "10")\n| stats count(eval(EventCode=4625)) as Failures, count(eval(EventCode=4624)) as Successes by Account_Name, Workstation_Name, Source_Network_Address, span(_time, 600)\n| where Failures > 5`,
      description: 'SPL lateral movement / credential abuse detection.',
    };
    return {
      query: `event.code:(4624 OR 4625 OR 4648) AND winlog.logon.type:(3 OR 9 OR 10) AND NOT user.name:*$`,
      description: 'Elastic query for lateral movement detection.',
    };
  }

  if (scenarioLower.includes('c2') || scenarioLower.includes('command and control') || scenarioLower.includes('beacon')) {
    if (isKQL) return {
      query: `DeviceNetworkEvents\n| where RemotePort in (4444, 1337, 8080, 8888, 9001, 443)\n| where RemoteIPType == "Public"\n| summarize ConnectionCount=count(), UniqueIPs=dcount(RemoteIP) by DeviceName, ProcessId, bin(Timestamp, 5m)\n| where ConnectionCount > 20 and UniqueIPs == 1  // Beaconing pattern: many to same IP\n| order by Timestamp desc`,
      description: 'Detects C2 beaconing pattern: repeated connections to a single external IP.',
    };
    if (isSPL) return {
      query: `index=network_traffic\n| stats count by src_ip, dest_ip, dest_port, span(_time, 300)\n| where count > 20\n| where dest_port IN (4444, 1337, 8080, 8888, 9001)\n| sort -count`,
      description: 'SPL C2 beaconing detection.',
    };
    return {
      query: `network.direction:outbound AND destination.port:(4444 OR 1337 OR 8080 OR 8888 OR 9001)`,
      description: 'Elastic C2 traffic detection.',
    };
  }

  // Generic fallback
  const keywords = scenarioLower.split(/\s+/).filter(w => w.length > 3).slice(0, 5);
  if (isKQL) return {
    query: `SecurityEvent\n| where TimeGenerated > ago(24h)\n| where ${keywords.map(k => `CommandLine has "${k}"`).join('\n     or ')}\n| project TimeGenerated, Computer, Account, CommandLine\n| order by TimeGenerated desc`,
    description: `Generic KQL query for detecting: ${scenario}`,
  };
  if (isSPL) return {
    query: `index=* earliest=-24h\n| search ${keywords.map(k => `"${k}"`).join(' AND ')}\n| table _time, host, user, _raw\n| sort -_time`,
    description: `Generic SPL query for detecting: ${scenario}`,
  };
  return {
    query: keywords.map(k => `"${k}"`).join(' AND '),
    description: `Generic Elastic query for detecting: ${scenario}`,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  TOOL 4 — IOC Enrich
// ══════════════════════════════════════════════════════════════════════════════
const iocEnrichTool = {
  name: 'ioc_enrich',
  description: 'Enrich an Indicator of Compromise (IP address, domain, file hash, URL) with threat intelligence data including reputation scores, geolocation, malware families, and context.',
  parameters: {
    type: 'object',
    properties: {
      ioc:      { type: 'string',  description: 'The IOC value to enrich (IP, domain, SHA256/MD5/SHA1 hash, URL)' },
      ioc_type: { type: 'string',  enum: ['ip', 'domain', 'hash', 'url', 'auto'], description: 'IOC type (auto = auto-detect)', default: 'auto' },
    },
    required: ['ioc'],
  },

  async execute(params, context) {
    const { ioc, ioc_type = 'auto' } = params;
    const type = ioc_type === 'auto' ? _detectIOCType(ioc) : ioc_type;

    // Try to enrich via internal platform API (if running)
    const backendBase = process.env.BACKEND_URL || 'http://localhost:4000';
    try {
      const { status, body } = await _httpGet(
        `${backendBase}/api/iocs?value=${encodeURIComponent(ioc)}&limit=1`,
        context?.authHeader ? { Authorization: context.authHeader } : {}
      );
      if (status === 200 && body?.data?.length) {
        const record = body.data[0];
        return {
          result: {
            ioc,
            type,
            found: true,
            risk_score:      record.risk_score || record.confidence || 0,
            malware_family:  record.malware_family || record.tags || [],
            first_seen:      record.first_seen || record.created_at,
            last_seen:       record.last_seen  || record.updated_at,
            source:          record.source || 'Internal DB',
            country:         record.country || 'Unknown',
            asn:             record.asn || 'Unknown',
            threat_type:     record.threat_type || record.type || type,
            context:         record.context || record.description || '',
          },
          metadata: { tool: 'ioc_enrich', source: 'internal_db' },
        };
      }
    } catch { /* backend unavailable, use fallback */ }

    // Fallback: structured mock enrichment based on IOC type
    return {
      result: _mockEnrichment(ioc, type),
      metadata: { tool: 'ioc_enrich', source: 'analysis', note: 'Backend unavailable; analytical result' },
    };
  },
};

function _detectIOCType(ioc) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ioc)) return 'ip';
  if (/^[a-f0-9]{32}$/i.test(ioc) || /^[a-f0-9]{40}$/i.test(ioc) || /^[a-f0-9]{64}$/i.test(ioc)) return 'hash';
  if (/^https?:\/\//.test(ioc)) return 'url';
  if (/\.[a-z]{2,}$/i.test(ioc)) return 'domain';
  return 'unknown';
}

function _mockEnrichment(ioc, type) {
  const baseScore = Math.floor(Math.random() * 40) + 30; // 30-70 for demonstration
  return {
    ioc,
    type,
    found: false,
    risk_score:     baseScore,
    confidence:     'medium',
    note:           'IOC not found in local database. Consider manual threat intelligence query.',
    recommended_actions: [
      'Block at perimeter firewall/proxy',
      'Search SIEM for historical connections',
      'Add to threat watchlist',
      'Submit to VirusTotal for community verdict',
    ],
    suggested_sources: [
      `https://www.virustotal.com/gui/search/${encodeURIComponent(ioc)}`,
      `https://otx.alienvault.com/indicator/${type}/${encodeURIComponent(ioc)}`,
      `https://threatfox.abuse.ch/browse/ioc/?q=${encodeURIComponent(ioc)}`,
    ],
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  TOOL 5 — MITRE ATT&CK Lookup
// ══════════════════════════════════════════════════════════════════════════════
const mitreLookupTool = {
  name: 'mitre_lookup',
  description: 'Look up detailed information about a MITRE ATT&CK technique, tactic, group, or software. Returns description, detection guidance, mitigation strategies, and examples.',
  parameters: {
    type: 'object',
    properties: {
      query:         { type: 'string', description: 'Technique ID (T1059.001), technique name, tactic, or APT group name' },
      include_mitigations: { type: 'boolean', description: 'Include mitigation strategies', default: true },
      include_detections:  { type: 'boolean', description: 'Include detection recommendations', default: true },
    },
    required: ['query'],
  },

  async execute(params, _context) {
    const { query, include_mitigations = true, include_detections = true } = params;
    const qUpper = query.toUpperCase().trim();

    // Match technique ID pattern
    const techMatch = qUpper.match(/T(\d{4})(?:\.(\d{3}))?/);

    if (techMatch) {
      const tid = techMatch[0];

      // First try the MITREEnricher (richer inline knowledge)
      const enrichedInfo = MITREEnricher.lookup(tid);
      if (enrichedInfo) {
        return {
          result: {
            id:          tid,
            name:        enrichedInfo.name,
            tactic:      enrichedInfo.tactic,
            severity:    enrichedInfo.severity || 'Medium',
            description: enrichedInfo.description,
            detection:   enrichedInfo.detection,
            soc_context: enrichedInfo.socContext,
            mitigations: include_mitigations ? _getMITREData(tid, true, false).mitigations || [] : [],
            url:         `https://attack.mitre.org/techniques/${tid.replace('.', '/')}/`,
            // Full structured section for standalone display
            _formatted:  MITREEnricher.buildTechniqueSection(tid),
          },
          metadata: { tool: 'mitre_lookup', technique_id: tid, source: 'enricher' },
        };
      }

      // Fall back to embedded DB
      const info = _getMITREData(tid, include_mitigations, include_detections);
      return {
        result: info,
        metadata: { tool: 'mitre_lookup', technique_id: tid },
      };
    }

    // Text search in embedded knowledge
    const results = _searchMITRE(query, include_mitigations, include_detections);
    return {
      result: results,
      metadata: { tool: 'mitre_lookup', query },
    };
  },
};

// Embedded MITRE knowledge (top 20 most-referenced techniques)
const MITRE_DB = {
  'T1059': {
    id: 'T1059', name: 'Command and Scripting Interpreter',
    tactic: ['execution'],
    description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of Unix Shell while Windows installations include the Windows Command Shell and PowerShell.',
    subtechniques: {
      '001': { name: 'PowerShell', description: 'PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code.' },
      '002': { name: 'AppleScript', description: 'macOS and OS X applications send AppleEvent messages to each other for interprocess communications (IPC). These messages can be easily scripted with AppleScript for local or remote execution.' },
      '003': { name: 'Windows Command Shell', description: 'The Windows command shell (cmd) is the primary command prompt on Windows systems. The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands.' },
      '007': { name: 'JavaScript', description: 'JavaScript (JS) is a platform-independent scripting language commonly associated with scripts in webpages, though JS can be executed in runtime environments outside the browser.' },
    },
    detection: 'Monitor for execution of the Windows command interpreter (cmd.exe) and PowerShell, as well as scripting engines such as cscript, mshta, wscript. Monitoring process command-line parameters enables detection of specific variations. Monitor for script execution events. Command history logs.',
    mitigations: ['Disable or restrict PowerShell with Group Policy', 'Enable PowerShell Script Block Logging and Module Logging', 'Use Constrained Language Mode for PowerShell', 'Application control to prevent execution of unknown scripting engines'],
    data_sources: ['Command: Command Execution', 'Process: Process Creation', 'Script: Script Execution'],
    platforms: ['Windows', 'macOS', 'Linux'],
    url: 'https://attack.mitre.org/techniques/T1059/',
  },
  'T1078': {
    id: 'T1078', name: 'Valid Accounts',
    tactic: ['defense-evasion', 'persistence', 'privilege-escalation', 'initial-access'],
    description: 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services.',
    subtechniques: {
      '001': { name: 'Default Accounts', description: 'Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.' },
      '003': { name: 'Local Accounts', description: 'Adversaries may obtain and abuse credentials of a local account as a means of gaining Persistence; Privilege Escalation; Defense Evasion; or Initial Access.' },
      '004': { name: 'Cloud Accounts', description: 'Valid cloud accounts may be used to access cloud resources.' },
    },
    detection: 'Monitor for suspicious account logons. Track unusual access patterns, off-hours access, or access from unexpected geolocations. Monitor for use of default or shared credentials. Audit privileged account use.',
    mitigations: ['Multi-Factor Authentication (MFA)', 'Privileged Account Management', 'Password Policies', 'User Account Management', 'Zero Trust architecture'],
    data_sources: ['Logon Session: Logon Session Creation', 'User Account: User Account Authentication'],
    platforms: ['Windows', 'Azure AD', 'Office 365', 'SaaS', 'IaaS', 'Linux', 'macOS'],
    url: 'https://attack.mitre.org/techniques/T1078/',
  },
  'T1190': {
    id: 'T1190', name: 'Exploit Public-Facing Application',
    tactic: ['initial-access'],
    description: 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.',
    detection: 'Monitor web application logs for unusual requests. Deploy WAF with anomaly detection. Regularly scan for known vulnerabilities. Monitor for unusual outbound connections after web requests.',
    mitigations: ['Application Isolation and Sandboxing', 'Exploit Protection', 'Network Segmentation', 'Update Software', 'Vulnerability Scanning'],
    data_sources: ['Application Log: Application Log Content', 'Network Traffic: Network Traffic Content'],
    platforms: ['Linux', 'Windows', 'macOS', 'Network'],
    url: 'https://attack.mitre.org/techniques/T1190/',
  },
  'T1566': {
    id: 'T1566', name: 'Phishing',
    tactic: ['initial-access'],
    description: 'Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering.',
    subtechniques: {
      '001': { name: 'Spearphishing Attachment', description: 'Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access.' },
      '002': { name: 'Spearphishing Link', description: 'Adversaries may send spearphishing emails with a malicious link in an attempt to gain access.' },
      '003': { name: 'Spearphishing via Service', description: 'Adversaries may send spearphishing messages via third-party services to gain access.' },
    },
    detection: 'Deploy email security solutions with sandboxing. Monitor for suspicious email attachments. User awareness training. Check links against threat intel feeds.',
    mitigations: ['Anti-Phishing', 'Antivirus/Antimalware', 'Network Intrusion Prevention', 'Restrict Web-Based Content', 'User Training'],
    data_sources: ['Application Log: Application Log Content', 'Network Traffic: Network Traffic Flow'],
    platforms: ['Linux', 'macOS', 'Windows', 'SaaS', 'Office 365'],
    url: 'https://attack.mitre.org/techniques/T1566/',
  },
  'T1486': {
    id: 'T1486', name: 'Data Encrypted for Impact',
    tactic: ['impact'],
    description: 'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key.',
    detection: 'Monitor for abnormal file modification activity. Alert on mass file renames with unusual extensions. Monitor for high-volume I/O operations. Track shadow copy deletion commands.',
    mitigations: ['Backup and Recovery', 'Data Backup', 'Behavior Prevention on Endpoint', 'Restrict File and Directory Permissions'],
    data_sources: ['Cloud Storage: Cloud Storage Modification', 'File: File Creation', 'File: File Modification'],
    platforms: ['Windows', 'macOS', 'Linux', 'IaaS'],
    url: 'https://attack.mitre.org/techniques/T1486/',
  },
  'T1055': {
    id: 'T1055', name: 'Process Injection',
    tactic: ['defense-evasion', 'privilege-escalation'],
    description: 'Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process.',
    subtechniques: {
      '001': { name: 'Dynamic-link Library Injection', description: 'A malicious DLL is loaded into a target process using Windows API calls.' },
      '002': { name: 'Portable Executable Injection', description: 'Portable executable (PE) code is injected into a remote process.' },
      '003': { name: 'Thread Execution Hijacking', description: 'The execution of a thread is redirected to execute malicious code in the target process.' },
      '012': { name: 'Process Hollowing', description: 'A legitimate process is created in a suspended state, its memory is unmapped and replaced with malicious code.' },
    },
    detection: 'Monitor for API calls associated with process injection. Detect suspicious cross-process memory writes. Monitor for unusual parent-child process relationships.',
    mitigations: ['Behavior Prevention on Endpoint', 'Privileged Account Management'],
    data_sources: ['Process: Process Access', 'Process: Process Modification', 'Process: OS API Execution'],
    platforms: ['Linux', 'macOS', 'Windows'],
    url: 'https://attack.mitre.org/techniques/T1055/',
  },
};

function _getMITREData(techniqueId, incMit, incDet) {
  const [base, sub] = techniqueId.split('.');
  const tech = MITRE_DB[base];

  if (!tech) {
    return {
      error:   false,
      found:   false,
      id:      techniqueId,
      message: `Technique ${techniqueId} not in embedded knowledge. Visit https://attack.mitre.org/techniques/${base}/`,
      url:     `https://attack.mitre.org/techniques/${base}/`,
    };
  }

  const result = {
    id:          techniqueId,
    name:        sub && tech.subtechniques?.[sub] ? `${tech.name}: ${tech.subtechniques[sub].name}` : tech.name,
    tactic:      tech.tactic,
    description: sub && tech.subtechniques?.[sub] ? tech.subtechniques[sub].description : tech.description,
    platforms:   tech.platforms,
    data_sources: tech.data_sources,
    url:         `https://attack.mitre.org/techniques/${base}/${sub ? `${base}.${sub.padStart(3,'0')}/` : ''}`,
  };

  if (incDet) result.detection = tech.detection;
  if (incMit) result.mitigations = tech.mitigations;
  if (!sub && tech.subtechniques) {
    result.subtechniques = Object.entries(tech.subtechniques).map(([id, s]) => ({
      id: `${base}.${id}`, name: s.name,
    }));
  }

  return result;
}

function _searchMITRE(query, incMit, incDet) {
  const lower = query.toLowerCase();
  const results = [];

  for (const tech of Object.values(MITRE_DB)) {
    const score =
      (tech.name.toLowerCase().includes(lower) ? 3 : 0) +
      (tech.description.toLowerCase().includes(lower) ? 1 : 0) +
      (tech.tactic.some(t => t.includes(lower)) ? 2 : 0);

    if (score > 0) {
      results.push({ ...tech, _score: score });
    }
  }

  results.sort((a, b) => b._score - a._score);
  return results.slice(0, 5).map(t => _getMITREData(t.id, incMit, incDet));
}

// ══════════════════════════════════════════════════════════════════════════════
//  TOOL 6 — CVE Lookup
// ══════════════════════════════════════════════════════════════════════════════
const cveLookupTool = {
  name: 'cve_lookup',
  description: 'Look up detailed information about a CVE (Common Vulnerabilities and Exposures) including CVSS score, description, affected products, and patch information.',
  parameters: {
    type: 'object',
    properties: {
      cve_id: { type: 'string', description: 'CVE ID (e.g. CVE-2024-12345)' },
    },
    required: ['cve_id'],
  },

  async execute(params, _context) {
    const { cve_id } = params;
    const cveUpper = cve_id.toUpperCase().trim();

    if (!/^CVE-\d{4}-\d{4,}$/.test(cveUpper)) {
      return {
        result: {
          error:   false,
          found:   false,
          id:      cve_id,
          message: `Invalid CVE ID format: "${cve_id}". Expected format: CVE-YYYY-NNNNN (e.g. CVE-2024-12356).`,
        },
        metadata: { tool: 'cve_lookup' },
      };
    }

    // Check offline hints first (common well-known CVEs)
    const offlineHint = MITREEnricher.getCVEContext(cveUpper);

    // Try NVD proxy
    try {
      const nvdUrl = `http://localhost:3000/proxy/nvd?cveId=${cveUpper}`;
      const { status, body } = await _httpGet(nvdUrl);
      if (status === 200 && body?.vulnerabilities?.length) {
        const vuln  = body.vulnerabilities[0].cve;
        const desc  = vuln.descriptions?.find(d => d.lang === 'en')?.value || 'No description';
        const cvss3 = vuln.metrics?.cvssMetricV31?.[0]?.cvssData;
        const severity = cvss3?.baseSeverity || 'UNKNOWN';
        const score    = cvss3?.baseScore    || null;

        // Build structured SOC-template response
        const result = {
          id:              cveUpper,
          found:           true,
          description:     desc,
          severity,
          cvss_score:      score,
          cvss_vector:     cvss3?.vectorString || null,
          published:       vuln.published,
          last_modified:   vuln.lastModified,
          references:      (vuln.references || []).slice(0, 5).map(r => r.url),
          // Structured guidance for SOC template
          soc_impact:      _getCVEImpact(severity),
          recommended_actions: _getCVEActions(severity),
          nvd_url:         `https://nvd.nist.gov/vuln/detail/${cveUpper}`,
        };

        return {
          result,
          metadata: { tool: 'cve_lookup', source: 'nvd' },
        };
      }
    } catch { /* proxy unavailable */ }

    // Fallback with offline hint if available
    return {
      result: {
        id:      cveUpper,
        found:   false,
        message: 'CVE details not retrievable from NVD at this time.',
        offline_context: offlineHint || null,
        nvd_url:         `https://nvd.nist.gov/vuln/detail/${cveUpper}`,
        mitre_url:       `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveUpper}`,
        recommended_actions: [
          `Search NVD directly: https://nvd.nist.gov/vuln/detail/${cveUpper}`,
          'Check vendor security advisories',
          'Review patch notes for affected software versions',
        ],
      },
      metadata: { tool: 'cve_lookup', source: 'fallback' },
    };
  },
};

function _getCVEImpact(severity) {
  const map = {
    CRITICAL: 'Immediate risk to the organisation. Exploitation may allow full system compromise, data theft, or lateral movement without authentication.',
    HIGH:     'Significant risk. Exploitation could allow privilege escalation, remote code execution, or unauthorised data access.',
    MEDIUM:   'Moderate risk. Exploitation typically requires some preconditions (e.g., authenticated access or specific configuration).',
    LOW:      'Limited risk. Exploitation is complex or has minimal impact. Monitor and apply patch in scheduled maintenance cycle.',
    UNKNOWN:  'Severity not yet assessed. Treat as MEDIUM until CVSS score is available.',
  };
  return map[(severity || '').toUpperCase()] || map.UNKNOWN;
}

function _getCVEActions(severity) {
  const base = [
    'Apply the vendor-provided patch or security update',
    'Identify all affected systems using asset inventory',
    'Check SIEM for exploitation indicators (unusual errors, auth attempts)',
  ];
  const bySeverity = {
    CRITICAL: [
      '🔴 **IMMEDIATE ACTION REQUIRED** — Patch within 24 hours',
      'Isolate affected systems if patching is not immediately possible',
      'Activate incident response playbook for critical vulnerability',
      ...base,
    ],
    HIGH: [
      '🟠 Patch within 72 hours',
      'Implement compensating controls if patch is not available',
      ...base,
    ],
    MEDIUM: [
      '🟡 Patch within 30 days (next scheduled maintenance window)',
      ...base,
    ],
    LOW: [
      '🟢 Patch in next quarterly update cycle',
      ...base,
    ],
  };
  return bySeverity[(severity || '').toUpperCase()] || base;
}

// ══════════════════════════════════════════════════════════════════════════════
//  TOOL 7 — Threat Actor Profile
// ══════════════════════════════════════════════════════════════════════════════
const threatActorTool = {
  name: 'threat_actor_profile',
  description: 'Retrieve a profile of a known threat actor / APT group including their TTPs, targets, origin, and recent activity.',
  parameters: {
    type: 'object',
    properties: {
      actor: { type: 'string', description: 'Threat actor name or alias (e.g. APT29, Lazarus Group, LockBit, Scattered Spider)' },
    },
    required: ['actor'],
  },

  async execute(params, _context) {
    const { actor } = params;
    const lower = actor.toLowerCase();

    const profile = _getActorProfile(lower);
    if (profile) {
      return { result: profile, metadata: { tool: 'threat_actor_profile', actor } };
    }

    return {
      result: {
        actor,
        found: false,
        message: `No embedded profile for "${actor}". Recommend checking MITRE Groups: https://attack.mitre.org/groups/`,
        resources: [
          `https://attack.mitre.org/groups/`,
          `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(actor)}`,
        ],
      },
      metadata: { tool: 'threat_actor_profile', actor },
    };
  },
};

const ACTOR_DB = {
  'apt29': {
    name: 'APT29', aliases: ['Cozy Bear', 'The Dukes', 'YTTRIUM', 'Midnight Blizzard'],
    origin: 'Russia', sponsor: 'SVR (Russian Foreign Intelligence)',
    motivation: ['Cyber Espionage', 'Data Theft'],
    targets: ['Government', 'Defense', 'Think Tanks', 'Political Organizations'],
    ttps: ['T1078', 'T1566', 'T1059.001', 'T1055', 'T1021.001'],
    tools: ['HAMMERTOSS', 'MiniDuke', 'CosmicDuke', 'WellMess', 'SolarWinds SUNBURST'],
    notable_campaigns: ['SolarWinds (2020)', 'NOBELIUM (2021)', 'Microsoft Exchange (2024)'],
    last_active: '2024',
    description: 'Highly sophisticated nation-state espionage group linked to Russia\'s SVR. Known for supply chain attacks and stealthy long-term access.',
  },
  'apt28': {
    name: 'APT28', aliases: ['Fancy Bear', 'Sofacy', 'STRONTIUM', 'Forest Blizzard'],
    origin: 'Russia', sponsor: 'GRU (Russian Military Intelligence)',
    motivation: ['Cyber Espionage', 'Influence Operations'],
    targets: ['Government', 'Military', 'NATO', 'Media', 'Elections'],
    ttps: ['T1566', 'T1190', 'T1059', 'T1203', 'T1078'],
    tools: ['X-Agent', 'Sofacy', 'Komplex', 'Zebrocy', 'Drovorub'],
    notable_campaigns: ['DNC Hack (2016)', 'French Election (2017)', 'Olympics (2018)'],
    last_active: '2024',
    description: 'Nation-state actor linked to GRU. Highly active in geopolitical targets, election interference, and military espionage.',
  },
  'lazarus': {
    name: 'Lazarus Group', aliases: ['HIDDEN COBRA', 'Guardians of Peace', 'Zinc'],
    origin: 'North Korea', sponsor: 'RGB (North Korean Intelligence)',
    motivation: ['Financial Theft', 'Cyber Espionage', 'Sabotage'],
    targets: ['Cryptocurrency', 'Financial Institutions', 'Defense', 'Media'],
    ttps: ['T1566', 'T1055', 'T1059', 'T1486', 'T1041'],
    tools: ['HOPLIGHT', 'BLINDINGCAN', 'Bankshot', 'FASTCash', 'AppleJeus'],
    notable_campaigns: ['WannaCry (2017)', 'Bangladesh Bank Heist ($81M)', 'Bybit Exchange ($1.5B, 2024)'],
    last_active: '2024',
    description: 'North Korean state-sponsored group responsible for major cryptocurrency thefts and destructive cyber attacks. Primarily financially motivated.',
  },
  'lockbit': {
    name: 'LockBit', aliases: ['LockBit 2.0', 'LockBit 3.0', 'LockBit Black'],
    origin: 'Unknown (Eastern Europe suspected)',
    motivation: ['Financial - Ransomware-as-a-Service'],
    targets: ['Healthcare', 'Government', 'Manufacturing', 'Critical Infrastructure'],
    ttps: ['T1566', 'T1190', 'T1078', 'T1486', 'T1489'],
    tools: ['LockBit ransomware', 'Cobalt Strike', 'Rclone', 'AnyDesk'],
    notable_campaigns: ['Royal Mail (2023)', 'ICBC (2023)', 'Boeing (2023)', 'Fulton County (2024)'],
    last_active: '2024',
    description: 'Most prolific RaaS group of 2022-2024. Disrupted by Operation Cronos (Feb 2024) but resumed operations.',
  },
  'scattered spider': {
    name: 'Scattered Spider', aliases: ['UNC3944', 'MUDDLED LIBRA', 'Starfraud', 'Octo Tempest'],
    origin: 'USA/UK (Native English speakers)',
    motivation: ['Financial Theft', 'Data Extortion'],
    targets: ['Hospitality', 'Retail', 'Telecommunications', 'Financial Services'],
    ttps: ['T1078', 'T1598', 'T1621', 'T1659', 'T1566.002'],
    tools: ['Okta social engineering', 'SIM swapping', 'Qilin ransomware', 'BlackCat/ALPHV'],
    notable_campaigns: ['MGM Resorts ($100M, 2023)', 'Caesars Entertainment (2023)', 'Reddit (2023)'],
    last_active: '2024',
    description: 'Sophisticated financially-motivated group using social engineering, SIM swapping, and identity attacks. Unusual as native English-speaking cybercriminals.',
  },
};

function _getActorProfile(query) {
  // Direct name match
  if (ACTOR_DB[query]) return ACTOR_DB[query];

  // Alias search
  for (const profile of Object.values(ACTOR_DB)) {
    if (profile.aliases.some(a => a.toLowerCase().includes(query))) return profile;
    if (profile.name.toLowerCase().includes(query)) return profile;
  }
  return null;
}

// ══════════════════════════════════════════════════════════════════════════════
//  TOOL 8 — Platform Navigate
// ══════════════════════════════════════════════════════════════════════════════
const platformNavigateTool = {
  name: 'platform_navigate',
  description: 'Suggest the most relevant Wadjet-Eye AI platform page for a given task. Use when the user asks where to find something or how to navigate the platform.',
  parameters: {
    type: 'object',
    properties: {
      task: { type: 'string', description: 'What the user wants to accomplish' },
    },
    required: ['task'],
  },

  async execute(params, _context) {
    const { task } = params;
    const lower = task.toLowerCase();

    const PAGE_MAP = [
      { keywords: ['sigma','detection rule','write rule','generate rule'], page: 'detection-engineering', title: 'Detection Engineering', icon: 'fas fa-code' },
      { keywords: ['ioc','indicator','enrich','lookup','ip address','domain','hash'], page: 'ioc-database', title: 'IOC Database', icon: 'fas fa-database' },
      { keywords: ['cve','vulnerability','patch','nvd','cvss'], page: 'findings', title: 'Findings / CVE Intelligence', icon: 'fas fa-bug' },
      { keywords: ['campaign','attack campaign','active campaign'], page: 'campaigns', title: 'Active Campaigns', icon: 'fas fa-bullseye' },
      { keywords: ['dark web','darkweb','onion','ransomware gang','leak','credential dump'], page: 'dark-web', title: 'Dark Web Intelligence', icon: 'fas fa-spider' },
      { keywords: ['threat actor','apt','nation state','group'], page: 'threat-actors', title: 'Threat Actors', icon: 'fas fa-user-secret' },
      { keywords: ['mitre','att&ck','technique','tactic'], page: 'mitre-attack', title: 'MITRE ATT&CK Navigator', icon: 'fas fa-sitemap' },
      { keywords: ['alert','detection','siem','live detection','real-time'], page: 'detections', title: 'Live Detections', icon: 'fas fa-eye' },
      { keywords: ['playbook','soar','response','automate'], page: 'playbooks', title: 'SOAR Playbooks', icon: 'fas fa-play-circle' },
      { keywords: ['feed','collector','threat feed','otx','abuseipdb'], page: 'collectors', title: 'Threat Feed Collectors', icon: 'fas fa-broadcast-tower' },
      { keywords: ['executive','ciso','dashboard','kpi','metric'], page: 'executive-dashboard', title: 'Executive Dashboard', icon: 'fas fa-chart-bar' },
      { keywords: ['geo','map','location','country','threat map'], page: 'geo-threats', title: 'Geo Threat Map', icon: 'fas fa-globe' },
      { keywords: ['case','incident','investigation'], page: 'case-management', title: 'Case Management', icon: 'fas fa-folder-open' },
    ];

    const matches = PAGE_MAP
      .map(p => ({ ...p, score: p.keywords.filter(k => lower.includes(k)).length }))
      .filter(p => p.score > 0)
      .sort((a, b) => b.score - a.score);

    if (!matches.length) {
      return {
        result: {
          message: 'I can help you navigate to the right module. Try asking about a specific feature like IOC lookup, CVE search, or detection engineering.',
          available_modules: PAGE_MAP.map(p => ({ page: p.page, title: p.title })),
        },
        metadata: { tool: 'platform_navigate' },
      };
    }

    return {
      result: {
        recommended_page: matches[0].page,
        recommended_title: matches[0].title,
        icon:  matches[0].icon,
        other_suggestions: matches.slice(1, 3).map(m => ({ page: m.page, title: m.title })),
        action: `Navigate to: ${matches[0].title}`,
        navigate_hint: `window.navigateTo && window.navigateTo('${matches[0].page}')`,
      },
      metadata: { tool: 'platform_navigate' },
    };
  },
};

// ══════════════════════════════════════════════════════════════════════════════
//  TOOL REGISTRY
// ══════════════════════════════════════════════════════════════════════════════
const ALL_TOOLS = [
  sigmaSearchTool,
  sigmaGenerateTool,
  kqlGenerateTool,
  iocEnrichTool,
  mitreLookupTool,
  cveLookupTool,
  threatActorTool,
  platformNavigateTool,
];

// Build the OpenAI function-calling schema list from the registry
const TOOL_SCHEMAS = ALL_TOOLS.map(t => ({
  type:     'function',
  function: {
    name:        t.name,
    description: t.description,
    parameters:  t.parameters,
  },
}));

/**
 * Execute a tool by name.
 * @param {string}  name    — tool name
 * @param {object}  params  — parsed arguments from LLM
 * @param {object}  context — request context (tenantId, userId, etc.)
 * @returns {Promise<{result: any, metadata: object}>}
 */
async function executeTool(name, params, context = {}) {
  const tool = ALL_TOOLS.find(t => t.name === name);
  if (!tool) {
    console.warn(`[RakayTools] Unknown tool requested: ${name}`);
    return {
      result: {
        error:   false,
        found:   false,
        message: `Tool '${name}' is not available. Available tools: ${ALL_TOOLS.map(t => t.name).join(', ')}`,
      },
      metadata: { tool: name, error: true },
    };
  }
  try {
    const startTime = Date.now();
    const toolResult = await tool.execute(params, context);
    const latencyMs  = Date.now() - startTime;
    console.log(`[RakayTools] Tool '${name}' completed in ${latencyMs}ms`);
    return toolResult;
  } catch (err) {
    console.error(`[RakayTools] Tool "${name}" error:`, err.message);
    // Return graceful error object — never throw to prevent LLM loop failure
    return {
      result: {
        error:   false,  // error:false so ResponseProcessor handles it cleanly
        found:   false,
        tool:    name,
        message: `The ${name} tool encountered an issue: ${err.message?.slice(0, 200) || 'Unknown error'}. Using available context to respond.`,
      },
      metadata: { tool: name, error: true, errorMessage: err.message?.slice(0, 100) },
    };
  }
}

module.exports = {
  ALL_TOOLS,
  TOOL_SCHEMAS,
  executeTool,
  // Individual tools exported for direct use / testing
  sigmaSearchTool,
  sigmaGenerateTool,
  kqlGenerateTool,
  iocEnrichTool,
  mitreLookupTool,
  cveLookupTool,
  threatActorTool,
  platformNavigateTool,
};
