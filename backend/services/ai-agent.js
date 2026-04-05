/**
 * ══════════════════════════════════════════════════════════
 *  ThreatPilot AI — AI Orchestration Agent v3.0
 *  backend/services/ai-agent.js
 *
 *  Design:
 *   - Accepts natural-language queries
 *   - Classifies intent via keyword patterns
 *   - Dispatches to appropriate "tool" functions
 *   - Returns structured JSON + human-readable explanation
 *
 *  Tools:
 *   ioc_lookup        — check IOC in DB + enrichment
 *   threat_actor_info — get actor profile + IOCs
 *   campaign_analysis — get campaign details
 *   risk_score        — calculate/explain risk score
 *   mitre_mapping     — map IOC/indicator to ATT&CK
 *   alert_summary     — summarize recent alerts
 *   feed_status       — check ingestion feed status
 *   ioc_search        — search IOCs by value/type
 *   cve_lookup        — look up CVE details
 *   correlation       — find related IOCs/actors
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const { supabase }   = require('../config/supabase');
const intelligence   = require('./intelligence');

// ══════════════════════════════════════════════════════════
//  INTENT CLASSIFICATION
// ══════════════════════════════════════════════════════════
const INTENT_PATTERNS = [
  {
    intent: 'ioc_lookup',
    patterns: [
      /check\s+(this\s+)?(ip|domain|url|hash|indicator)\s+/i,
      /lookup\s+/i,
      /is\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+(malicious|safe|dangerous)/i,
      /analyse?\s+/i,
      /what\s+is\s+\d{1,3}\.\d{1,3}/i,
      /[0-9a-f]{32,64}/i,  // hash
      /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP
    ],
    extract: extractIOCFromQuery,
  },
  {
    intent: 'threat_actor_info',
    patterns: [
      /who\s+is\s+(apt|ta|group|lazarus|fin|sandworm)/i,
      /threat\s+actor/i,
      /actor\s+profile/i,
      /about\s+(apt|ta)\d+/i,
      /tell\s+me\s+about\s+.+\s+group/i,
    ],
    extract: extractActorFromQuery,
  },
  {
    intent: 'campaign_analysis',
    patterns: [
      /campaign/i,
      /operation/i,
      /active\s+campaign/i,
      /recent\s+attack/i,
    ],
  },
  {
    intent: 'alert_summary',
    patterns: [
      /show\s+(top|latest|recent)\s+.*(alert|threat)/i,
      /active\s+threat/i,
      /threat\s+summary/i,
      /dashboard/i,
      /what.*(happening|going on|threats)/i,
      /summary/i,
    ],
  },
  {
    intent: 'risk_score',
    patterns: [
      /risk\s+score/i,
      /how\s+dangerous/i,
      /risk\s+level/i,
      /threat\s+level/i,
      /score\s+for/i,
    ],
    extract: extractIOCFromQuery,
  },
  {
    intent: 'mitre_mapping',
    patterns: [
      /mitre/i,
      /att&ck/i,
      /technique/i,
      /tactic/i,
      /t\d{4}/i,
    ],
    extract: extractIOCFromQuery,
  },
  {
    intent: 'feed_status',
    patterns: [
      /feed\s+status/i,
      /ingestion/i,
      /otx\s+status/i,
      /last\s+update/i,
      /feed\s+log/i,
      /collector/i,
    ],
  },
  {
    intent: 'cve_lookup',
    patterns: [
      /cve-\d{4}-\d+/i,
      /vulnerabilit/i,
      /exploit/i,
      /patch/i,
      /cvss/i,
    ],
    extract: extractCVEFromQuery,
  },
  {
    intent: 'ioc_search',
    patterns: [
      /show\s+(all|top|list|recent)\s+ioc/i,
      /malicious\s+ip/i,
      /high\s+risk\s+ioc/i,
      /find\s+ioc/i,
    ],
  },
  {
    intent: 'correlation',
    patterns: [
      /correlat/i,
      /related\s+to/i,
      /connection/i,
      /linked\s+to/i,
      /graph/i,
    ],
    extract: extractIOCFromQuery,
  },
];

// ── Extract IOC value from natural language ───────────────
function extractIOCFromQuery(query) {
  // IP address
  const ipMatch = query.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  if (ipMatch) return { value: ipMatch[1], type: 'ip' };

  // SHA256
  const sha256Match = query.match(/\b([0-9a-fA-F]{64})\b/);
  if (sha256Match) return { value: sha256Match[1].toLowerCase(), type: 'hash_sha256' };

  // MD5
  const md5Match = query.match(/\b([0-9a-fA-F]{32})\b/);
  if (md5Match) return { value: md5Match[1].toLowerCase(), type: 'hash_md5' };

  // Domain
  const domainMatch = query.match(/\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/i);
  if (domainMatch && !domainMatch[1].includes(' ')) {
    return { value: domainMatch[1].toLowerCase(), type: 'domain' };
  }

  // URL
  const urlMatch = query.match(/(https?:\/\/[^\s]+)/i);
  if (urlMatch) return { value: urlMatch[1].toLowerCase(), type: 'url' };

  return null;
}

function extractActorFromQuery(query) {
  const match = query.match(/\b(apt\d+|ta\d+|fin\d+|lazarus|sandworm|cozy\s*bear|fancy\s*bear|[a-z0-9-]+\s*group)\b/i);
  return match ? match[1].trim() : null;
}

function extractCVEFromQuery(query) {
  const match = query.match(/\b(cve-\d{4}-\d{4,})\b/i);
  return match ? match[1].toUpperCase() : null;
}

// ── Classify query intent ─────────────────────────────────
function classifyIntent(query) {
  for (const pattern of INTENT_PATTERNS) {
    for (const regex of pattern.patterns) {
      if (regex.test(query)) {
        return {
          intent:   pattern.intent,
          extracted: pattern.extract ? pattern.extract(query) : null,
        };
      }
    }
  }
  return { intent: 'general', extracted: null };
}

// ══════════════════════════════════════════════════════════
//  TOOL FUNCTIONS
// ══════════════════════════════════════════════════════════

// Tool: IOC Lookup
async function toolIOCLookup(ioc, tenantId) {
  if (!ioc?.value) {
    return {
      success: false,
      message: 'No IOC value found in query. Please specify an IP, domain, URL, or hash.',
    };
  }

  // Check DB first
  const { data: dbIOC } = await supabase
    .from('iocs')
    .select('*')
    .eq('tenant_id', tenantId)
    .eq('value', ioc.value.toLowerCase())
    .single();

  // Attempt live enrichment if keys available
  let enrichData = {};
  try {
    const results = await intelligence.autoEnrichIOC({ value: ioc.value, type: ioc.type });
    enrichData = results?.enrichment || {};
  } catch (_) {}

  const riskData  = intelligence.calculateRiskScore(enrichData, dbIOC);
  const riskScore = typeof riskData === 'object' ? riskData.score : (dbIOC?.risk_score || riskData);
  const mitre     = await intelligence.mapToMITRE({
    value: ioc.value, type: ioc.type,
    tags: dbIOC?.tags || [],
    enrichment_data: enrichData,
  });

  const reputation = riskScore >= 70 ? 'malicious' :
                     riskScore >= 40 ? 'suspicious' : 'clean';

  const explanation = generateIOCExplanation(ioc, riskScore, reputation, enrichData, mitre, dbIOC);

  return {
    success:     true,
    tool:        'ioc_lookup',
    ioc_value:   ioc.value,
    ioc_type:    ioc.type,
    found_in_db: !!dbIOC,
    reputation,
    risk_score:  riskScore,
    risk_breakdown: typeof riskData === 'object' ? riskData.breakdown : null,
    mitre_techniques: mitre,
    enrichment:  sanitizeEnrichment(enrichData),
    db_record:   dbIOC ? {
      id:            dbIOC.id,
      threat_actor:  dbIOC.threat_actor,
      malware_family:dbIOC.malware_family,
      country:       dbIOC.country,
      last_seen:     dbIOC.last_seen,
      tags:          dbIOC.tags,
    } : null,
    explanation,
  };
}

// Tool: Threat Actor Info
async function toolThreatActorInfo(actorName, tenantId) {
  if (!actorName) {
    // Return top actors
    const { data: actors } = await supabase
      .from('threat_actors')
      .select('id, name, motivation, sophistication, origin_country, last_seen, target_sectors')
      .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
      .order('updated_at', { ascending: false })
      .limit(10);

    return {
      success: true,
      tool:    'threat_actor_info',
      actors:  actors || [],
      explanation: actors?.length
        ? `Found ${actors.length} tracked threat actors. Top actors: ${actors.slice(0, 3).map(a => a.name).join(', ')}.`
        : 'No threat actors in the database yet. Run threat intelligence feeds to populate actor data.',
    };
  }

  const { data: actor } = await supabase
    .from('threat_actors')
    .select(`
      *,
      iocs(id, value, type, risk_score, last_seen)
    `)
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .ilike('name', `%${actorName}%`)
    .single();

  if (!actor) {
    return {
      success:     false,
      tool:        'threat_actor_info',
      actor_name:  actorName,
      explanation: `No information found for threat actor '${actorName}'. This actor may not be tracked yet.`,
    };
  }

  const explanation = `
${actor.name} is a ${actor.sophistication || 'unknown'}-sophistication threat actor
with ${actor.motivation || 'unknown'} motivation, believed to originate from ${actor.origin_country || 'unknown'}.
They target: ${(actor.target_sectors || []).join(', ') || 'various sectors'}.
Known TTPs: ${(actor.ttps || []).slice(0, 5).join(', ') || 'unknown'}.
Associated malware: ${(actor.malware || []).join(', ') || 'unknown'}.
${actor.iocs?.length ? `${actor.iocs.length} active IOCs linked to this actor.` : 'No IOCs currently linked.'}
  `.trim();

  return {
    success: true,
    tool:    'threat_actor_info',
    actor,
    explanation,
  };
}

// Tool: Alert Summary
async function toolAlertSummary(tenantId) {
  const [alerts, stats] = await Promise.all([
    supabase.from('alerts')
      .select('id, title, severity, status, type, ioc_value, created_at')
      .eq('tenant_id', tenantId)
      .in('status', ['open', 'in_progress'])
      .order('created_at', { ascending: false })
      .limit(10),
    supabase.from('alerts')
      .select('severity, status')
      .eq('tenant_id', tenantId)
      .gte('created_at', new Date(Date.now() - 24 * 3600000).toISOString()),
  ]);

  const alertData = alerts.data || [];
  const statsData = stats.data  || [];

  const critical = statsData.filter(a => a.severity === 'critical').length;
  const high     = statsData.filter(a => a.severity === 'high').length;
  const open     = statsData.filter(a => a.status === 'open').length;

  const explanation = `
In the last 24 hours: ${statsData.length} total alerts — ${critical} critical, ${high} high severity.
Currently open/active: ${open} alerts requiring attention.
${alertData.length > 0 ? `\nTop active alerts:\n${alertData.slice(0, 5).map(a => `• [${a.severity?.toUpperCase()}] ${a.title}`).join('\n')}` : 'No active alerts.'}
  `.trim();

  return {
    success:       true,
    tool:          'alert_summary',
    active_alerts: alertData,
    stats_24h:     { total: statsData.length, critical, high, open },
    explanation,
  };
}

// Tool: Feed Status
async function toolFeedStatus(tenantId) {
  const { data: logs } = await supabase
    .from('feed_logs')
    .select('feed_name, status, started_at, finished_at, iocs_new, iocs_updated, error_message')
    .eq('tenant_id', tenantId)
    .order('started_at', { ascending: false })
    .limit(30);

  const latest = {};
  for (const log of (logs || [])) {
    if (!latest[log.feed_name]) latest[log.feed_name] = log;
  }

  const feeds = Object.values(latest);
  const healthy = feeds.filter(f => f.status === 'success').length;
  const errors  = feeds.filter(f => f.status === 'error').length;

  const explanation = feeds.length === 0
    ? 'No feed ingestion has run yet. Configure API keys and trigger feeds from the Collectors tab.'
    : `${feeds.length} feed(s) tracked. ${healthy} healthy, ${errors} with errors.\n${
        feeds.map(f => `• ${f.feed_name}: ${f.status} (${f.iocs_new || 0} new IOCs)`).join('\n')
      }`;

  return {
    success:   true,
    tool:      'feed_status',
    feeds,
    summary:   { total: feeds.length, healthy, errors },
    explanation,
  };
}

// Tool: CVE Lookup
async function toolCVELookup(cveId, tenantId) {
  const { data: vuln } = await supabase
    .from('vulnerabilities')
    .select('*')
    .eq('cve_id', cveId)
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .single();

  if (!vuln) {
    return {
      success:     false,
      tool:        'cve_lookup',
      cve_id:      cveId,
      explanation: `${cveId} not found in database. Try triggering the NVD feed to fetch latest CVE data.`,
    };
  }

  const explanation = `
${vuln.cve_id}: ${vuln.description?.slice(0, 200) || 'No description'}...
CVSS Score: ${vuln.cvss_score} (${vuln.severity?.toUpperCase()})
Exploited in the wild: ${vuln.exploited_in_wild ? 'YES ⚠️' : 'No'}
Patch available: ${vuln.patch_available ? 'Yes ✓' : 'No - check vendor advisory'}
Affected products: ${(vuln.affected_products || []).slice(0, 3).join(', ')}
  `.trim();

  return { success: true, tool: 'cve_lookup', vulnerability: vuln, explanation };
}

// Tool: IOC Search
async function toolIOCSearch(tenantId, filters = {}) {
  let q = supabase
    .from('iocs')
    .select('id, value, type, risk_score, reputation, threat_actor, malware_family, country, last_seen, tags')
    .eq('tenant_id', tenantId)
    .eq('status', 'active')
    .order('risk_score', { ascending: false })
    .limit(20);

  if (filters.type) q = q.eq('type', filters.type);
  if (filters.min_risk) q = q.gte('risk_score', filters.min_risk);
  if (filters.reputation) q = q.eq('reputation', filters.reputation);

  const { data: iocs, count } = await q;

  const explanation = `Found ${iocs?.length || 0} IOCs matching your criteria.${
    iocs?.length > 0 ? `\nTop high-risk: ${iocs.slice(0, 3).map(i => `${i.value} (score: ${i.risk_score})`).join(', ')}` : ''
  }`;

  return {
    success:     true,
    tool:        'ioc_search',
    iocs:        iocs || [],
    total:       count || iocs?.length || 0,
    explanation,
  };
}

// Tool: Correlation
async function toolCorrelation(ioc, tenantId) {
  if (!ioc?.value) {
    return {
      success: false,
      tool: 'correlation',
      explanation: 'Please specify an IOC value to correlate.',
    };
  }

  const { data: dbIOC } = await supabase
    .from('iocs')
    .select('id, value, type, threat_actor, malware_family, tags, enrichment_data')
    .eq('tenant_id', tenantId)
    .eq('value', ioc.value.toLowerCase())
    .single();

  if (!dbIOC) {
    return {
      success: false,
      tool: 'correlation',
      explanation: `IOC ${ioc.value} not found in database.`,
    };
  }

  const [relationships, relatedIOCs, linkedAlerts] = await Promise.all([
    // Direct graph relationships
    supabase.from('ioc_relationships')
      .select('*')
      .eq('tenant_id', tenantId)
      .or(`source_id.eq.${dbIOC.id},target_id.eq.${dbIOC.id}`)
      .limit(20),

    // IOCs sharing same actor/malware
    dbIOC.threat_actor ? supabase.from('iocs')
      .select('id, value, type, risk_score, reputation')
      .eq('tenant_id', tenantId)
      .eq('threat_actor', dbIOC.threat_actor)
      .neq('id', dbIOC.id)
      .limit(10) : { data: [] },

    // Alerts referencing this IOC
    supabase.from('alerts')
      .select('id, title, severity, status, created_at')
      .eq('tenant_id', tenantId)
      .eq('ioc_value', ioc.value)
      .order('created_at', { ascending: false })
      .limit(5),
  ]);

  const explanation = `
Correlation analysis for ${ioc.value}:
• Direct relationships: ${relationships.data?.length || 0}
• Related IOCs (same actor/malware): ${relatedIOCs.data?.length || 0}
• Linked alerts: ${linkedAlerts.data?.length || 0}
${dbIOC.threat_actor ? `\nLinked to threat actor: ${dbIOC.threat_actor}` : ''}
${dbIOC.malware_family ? `Malware family: ${dbIOC.malware_family}` : ''}
  `.trim();

  return {
    success:         true,
    tool:            'correlation',
    ioc:             dbIOC,
    relationships:   relationships.data || [],
    related_iocs:    relatedIOCs.data   || [],
    linked_alerts:   linkedAlerts.data  || [],
    explanation,
  };
}

// ══════════════════════════════════════════════════════════
//  MAIN QUERY FUNCTION
// ══════════════════════════════════════════════════════════
async function query(userQuery, context = {}) {
  const { tenantId, user } = context;
  const t0 = Date.now();

  if (!tenantId) {
    return {
      success: false,
      error:   'No tenant context provided',
      explanation: 'Unable to process query without tenant context.',
    };
  }

  // Save to ai_sessions
  const sessionId = context.sessionId;

  // Classify intent
  const { intent, extracted } = classifyIntent(userQuery);

  console.log(`[AI Agent] Query: "${userQuery.slice(0, 80)}" → intent: ${intent}`);

  let result;

  try {
    switch (intent) {
      case 'ioc_lookup':
      case 'risk_score':
      case 'mitre_mapping': {
        const ioc = extracted || extractIOCFromQuery(userQuery);
        result = await toolIOCLookup(ioc, tenantId);
        break;
      }

      case 'threat_actor_info': {
        const actorName = extracted;
        result = await toolThreatActorInfo(actorName, tenantId);
        break;
      }

      case 'campaign_analysis': {
        const { data: campaigns } = await supabase
          .from('campaigns')
          .select('*, threat_actors(name)')
          .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
          .eq('status', 'active')
          .order('updated_at', { ascending: false })
          .limit(10);

        result = {
          success: true,
          tool: 'campaign_analysis',
          campaigns: campaigns || [],
          explanation: campaigns?.length
            ? `${campaigns.length} active campaign(s) tracked: ${campaigns.slice(0, 3).map(c => c.name).join(', ')}`
            : 'No active campaigns tracked. Run threat feeds to populate campaign data.',
        };
        break;
      }

      case 'alert_summary':
        result = await toolAlertSummary(tenantId);
        break;

      case 'feed_status':
        result = await toolFeedStatus(tenantId);
        break;

      case 'cve_lookup': {
        const cveId = extracted || extractCVEFromQuery(userQuery);
        result = await toolCVELookup(cveId, tenantId);
        break;
      }

      case 'ioc_search': {
        const filters = {};
        if (/malicious/i.test(userQuery)) filters.reputation = 'malicious';
        if (/high.?risk/i.test(userQuery)) filters.min_risk = 70;
        if (/\bip\b/i.test(userQuery))     filters.type = 'ip';
        if (/domain/i.test(userQuery))     filters.type = 'domain';
        if (/hash/i.test(userQuery))       filters.type = 'hash_sha256';
        result = await toolIOCSearch(tenantId, filters);
        break;
      }

      case 'correlation': {
        const ioc = extracted || extractIOCFromQuery(userQuery);
        result = await toolCorrelation(ioc, tenantId);
        break;
      }

      default: {
        // General query — return platform overview
        const [alertResult, feedResult] = await Promise.all([
          toolAlertSummary(tenantId),
          toolFeedStatus(tenantId),
        ]);

        result = {
          success: true,
          tool:    'platform_overview',
          alerts:  alertResult,
          feeds:   feedResult,
          explanation: `
I can help you with:
• **IOC Lookup**: "Check IP 1.2.3.4" or "Is domain evil.com malicious?"
• **Threat Actor**: "Who is APT29?" or "Tell me about Lazarus Group"
• **Campaign Analysis**: "Show active campaigns"
• **Alert Summary**: "Show top threats" or "What's happening?"
• **Risk Score**: "Risk score for 185.220.101.45"
• **MITRE Mapping**: "Map this IP to MITRE ATT&CK"
• **Feed Status**: "Check feed status"
• **CVE Lookup**: "Tell me about CVE-2024-3400"

${alertResult.explanation}
          `.trim(),
        };
      }
    }
  } catch (err) {
    console.error('[AI Agent] Tool error:', err.message);
    result = {
      success:     false,
      error:       err.message,
      explanation: `I encountered an error processing your query: ${err.message}. Please try again.`,
    };
  }

  const processingMs = Date.now() - t0;

  return {
    ...result,
    query:         userQuery,
    intent,
    processing_ms: processingMs,
    timestamp:     new Date().toISOString(),
    agent_version: '3.0',
  };
}

// ── Helper: generate IOC explanation ─────────────────────
function generateIOCExplanation(ioc, riskScore, reputation, enrichData, mitre, dbRecord) {
  const lines = [];

  lines.push(`**${ioc.value}** (${ioc.type})`);
  lines.push('');

  const repEmoji = { malicious: '🔴', suspicious: '🟡', clean: '🟢' };
  lines.push(`Reputation: ${repEmoji[reputation] || '⚪'} **${reputation.toUpperCase()}** (Risk Score: ${riskScore}/100)`);

  if (mitre?.length > 0) {
    lines.push(`MITRE ATT&CK: ${mitre.join(', ')}`);
  }

  // Source-specific details
  const vt = enrichData['VirusTotal'];
  if (vt) {
    lines.push(`VirusTotal: ${vt.malicious_count || 0}/${vt.total_engines || 0} engines flagged`);
  }

  const abuse = enrichData['AbuseIPDB'];
  if (abuse) {
    lines.push(`AbuseIPDB: Score ${abuse.abuse_score || 0}/100, ${abuse.total_reports || 0} reports`);
    if (abuse.country) lines.push(`Origin: ${abuse.country}`);
    if (abuse.isp)     lines.push(`ISP: ${abuse.isp}`);
  }

  const otx = enrichData['AlienVault OTX'];
  if (otx) {
    lines.push(`AlienVault OTX: ${otx.pulse_count || 0} threat pulses`);
  }

  if (dbRecord?.threat_actor)   lines.push(`Threat Actor: ${dbRecord.threat_actor}`);
  if (dbRecord?.malware_family) lines.push(`Malware: ${dbRecord.malware_family}`);
  if (dbRecord?.last_seen)      lines.push(`Last seen: ${new Date(dbRecord.last_seen).toLocaleDateString()}`);

  if (riskScore >= 70) {
    lines.push('');
    lines.push('⚠️ **Recommendation**: Block this indicator immediately. Create an alert and investigate affected systems.');
  } else if (riskScore >= 40) {
    lines.push('');
    lines.push('⚠️ **Recommendation**: Monitor this indicator. Consider additional enrichment before blocking.');
  } else {
    lines.push('');
    lines.push('✅ **Recommendation**: Indicator appears clean but continue monitoring.');
  }

  return lines.join('\n');
}

function sanitizeEnrichment(data) {
  // Remove raw/verbose fields for cleaner API response
  const out = {};
  for (const [key, val] of Object.entries(data)) {
    if (val && typeof val === 'object') {
      const { raw, raw_data, ...clean } = val;
      out[key] = clean;
    }
  }
  return out;
}

module.exports = { query, classifyIntent, extractIOCFromQuery };
