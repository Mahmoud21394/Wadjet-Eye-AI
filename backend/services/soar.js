/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Lightweight SOAR Engine v3.0
 *  backend/services/soar.js
 *
 *  Capabilities:
 *   1. Rule-based automation (DB-driven soar_rules)
 *   2. Auto-enrich new IOCs via enrichment service
 *   3. Auto-flag high-risk indicators → create alerts
 *   4. Auto-create cases for critical alerts
 *   5. IOC expiry management
 *   6. Cross-feed correlation
 *   7. SOAR execution logging
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const { supabase }   = require('../config/supabase');
const intelligence   = require('./intelligence');

// ── Constants ─────────────────────────────────────────────
const HIGH_RISK_THRESHOLD = 70;   // risk_score ≥ 70 → auto-alert
const CRITICAL_THRESHOLD  = 85;   // risk_score ≥ 85 → auto-case
const ENRICH_BATCH_SIZE   = 10;   // IOCs to enrich per SOAR run
const ALERT_COOLDOWN_HOURS = 24;  // Don't re-alert same IOC within 24h

// ════════════════════════════════════════════════════════════
//  1. RUN SOAR RULES (main entry point called by scheduler)
// ════════════════════════════════════════════════════════════
async function runRules(tenantId) {
  console.log(`[SOAR] Running rules for tenant ${tenantId.slice(0, 8)}...`);

  const [enrichResult, flagResult, caseResult] = await Promise.allSettled([
    autoEnrichNewIOCs(tenantId),
    autoFlagHighRiskIOCs(tenantId),
    autoCreateCriticalCases(tenantId),
  ]);

  const stats = {
    enriched:    enrichResult.value  || 0,
    flagged:     flagResult.value    || 0,
    cases_created: caseResult.value  || 0,
    errors:      [enrichResult, flagResult, caseResult]
      .filter(r => r.status === 'rejected')
      .map(r => r.reason?.message),
  };

  // Load and execute custom DB rules
  const customStats = await runCustomRules(tenantId);
  stats.custom_executions = customStats;

  console.log(`[SOAR] Done — enriched:${stats.enriched} flagged:${stats.flagged} cases:${stats.cases_created}`);
  return stats;
}

// ════════════════════════════════════════════════════════════
//  2. AUTO-ENRICH NEW IOCs
//     Find IOCs with risk_score = 0 and no enrichment_data
//     Call intel enrichment (VirusTotal/AbuseIPDB/OTX/Shodan)
// ════════════════════════════════════════════════════════════
async function autoEnrichNewIOCs(tenantId) {
  const { data: iocs, error } = await supabase
    .from('iocs')
    .select('id, value, type, risk_score, enrichment_data, source')
    .eq('tenant_id', tenantId)
    .eq('status', 'active')
    .or('risk_score.eq.0,enrichment_data.eq.{}')
    .in('type', ['ip', 'domain', 'url', 'hash_sha256', 'hash_md5'])
    .order('created_at', { ascending: false })
    .limit(ENRICH_BATCH_SIZE);

  if (error || !iocs?.length) return 0;

  let enrichedCount = 0;

  for (const ioc of iocs) {
    try {
      // Skip if enrichment_data is populated
      if (ioc.enrichment_data && Object.keys(ioc.enrichment_data).length > 2) continue;

      const results = await intelligence.autoEnrichIOCObject(ioc);
      if (!results) continue;

      const riskData = intelligence.calculateRiskScore(results.enrichment || {}, ioc);
      const newScore = typeof riskData === 'object' ? riskData.score : riskData;
      const mitre    = await intelligence.mapToMITRE(ioc);

      await supabase
        .from('iocs')
        .update({
          risk_score:      newScore || ioc.risk_score,
          enrichment_data: results.enrichment || {},
          reputation:      newScore >= 70 ? 'malicious' : newScore >= 40 ? 'suspicious' : ioc.reputation || 'unknown',
          updated_at:      new Date().toISOString(),
        })
        .eq('id', ioc.id);

      enrichedCount++;

      // Store relationships from MITRE mapping
      if (mitre?.length > 0) {
        await storeIOCMITRERelationships(tenantId, ioc.id, mitre);
      }

      // Throttle to avoid API rate limits
      await _sleep(500);
    } catch (err) {
      console.warn(`[SOAR] Enrich failed for ${ioc.value}: ${err.message}`);
    }
  }

  return enrichedCount;
}

// ════════════════════════════════════════════════════════════
//  3. AUTO-FLAG HIGH-RISK IOCs → CREATE ALERTS
// ════════════════════════════════════════════════════════════
async function autoFlagHighRiskIOCs(tenantId) {
  const cutoff = new Date(Date.now() - ALERT_COOLDOWN_HOURS * 3600000).toISOString();

  // Find high-risk IOCs without recent alerts
  const { data: iocs, error } = await supabase
    .from('iocs')
    .select('id, value, type, risk_score, reputation, threat_actor, malware_family, country, source, enrichment_data')
    .eq('tenant_id', tenantId)
    .eq('status', 'active')
    .gte('risk_score', HIGH_RISK_THRESHOLD)
    .neq('reputation', 'benign')
    .gt('updated_at', cutoff)
    .limit(20);

  if (error || !iocs?.length) return 0;

  let flaggedCount = 0;

  for (const ioc of iocs) {
    try {
      // Check if an alert already exists for this IOC recently
      const { count } = await supabase
        .from('alerts')
        .select('id', { count: 'exact', head: true })
        .eq('tenant_id', tenantId)
        .eq('ioc_value', ioc.value)
        .gt('created_at', cutoff);

      if (count && count > 0) continue; // Already alerted

      const severity = ioc.risk_score >= CRITICAL_THRESHOLD ? 'critical' :
                       ioc.risk_score >= 80                  ? 'high'     : 'medium';

      const title = buildAlertTitle(ioc);
      const desc  = buildAlertDescription(ioc);

      const { error: alertErr } = await supabase
        .from('alerts')
        .insert({
          tenant_id:       tenantId,
          title,
          description:     desc,
          severity,
          status:          'open',
          type:            mapIOCTypeToAlertType(ioc.type),
          ioc_value:       ioc.value,
          ioc_type:        ioc.type,
          source:          'SOAR Auto-Detect',
          metadata: {
            auto_generated:  true,
            risk_score:      ioc.risk_score,
            threat_actor:    ioc.threat_actor,
            malware_family:  ioc.malware_family,
            country:         ioc.country,
            soar_rule:       'auto_flag_high_risk',
          },
        });

      if (!alertErr) flaggedCount++;
    } catch (err) {
      console.warn(`[SOAR] Flag failed for ${ioc.value}: ${err.message}`);
    }
  }

  return flaggedCount;
}

// ════════════════════════════════════════════════════════════
//  4. AUTO-CREATE CASES FOR CRITICAL ALERTS
// ════════════════════════════════════════════════════════════
async function autoCreateCriticalCases(tenantId) {
  // Find critical open alerts without a case
  const { data: alerts, error } = await supabase
    .from('alerts')
    .select('id, title, description, severity, ioc_value, ioc_type, metadata, created_at')
    .eq('tenant_id', tenantId)
    .eq('severity', 'critical')
    .eq('status', 'open')
    .is('case_id', null)
    .gte('created_at', new Date(Date.now() - 2 * 3600000).toISOString()) // Last 2h
    .limit(5);

  if (error || !alerts?.length) return 0;

  let createdCount = 0;

  for (const alert of alerts) {
    try {
      const { data: caseData, error: caseErr } = await supabase
        .from('cases')
        .insert({
          tenant_id:   tenantId,
          title:       `[AUTO] ${alert.title}`,
          description: `Automatically created case for critical alert.\n\n${alert.description || ''}`,
          severity:    'critical',
          status:      'open',
          priority:    'p1',
          sla_hours:   2,
          source:      'soar',
          metadata: {
            auto_created:    true,
            source_alert_id: alert.id,
            soar_rule:       'auto_case_critical',
          },
        })
        .select('id')
        .single();

      if (!caseErr && caseData) {
        // Link alert to case
        await supabase
          .from('alerts')
          .update({ case_id: caseData.id, status: 'in_progress' })
          .eq('id', alert.id);

        // Add IOC to case if available
        if (alert.ioc_value) {
          const { data: ioc } = await supabase
            .from('iocs')
            .select('id')
            .eq('tenant_id', tenantId)
            .eq('value', alert.ioc_value)
            .single();

          if (ioc) {
            try {
              await supabase.from('case_iocs').insert({
                case_id: caseData.id,
                ioc_id:  ioc.id,
                notes:   'Auto-linked by SOAR',
              });
            } catch (_) { /* ignore dup */ }
          }
        }

        createdCount++;
      }
    } catch (err) {
      console.warn(`[SOAR] Case creation failed for alert ${alert.id}: ${err.message}`);
    }
  }

  return createdCount;
}

// ════════════════════════════════════════════════════════════
//  5. CUSTOM DB-DRIVEN RULES
// ════════════════════════════════════════════════════════════
async function runCustomRules(tenantId) {
  const { data: rules, error } = await supabase
    .from('soar_rules')
    .select('*')
    .eq('tenant_id', tenantId)
    .eq('enabled', true)
    .order('priority', { ascending: true });

  if (error || !rules?.length) return [];

  const executions = [];

  for (const rule of rules) {
    try {
      const result = await executeRule(rule, tenantId);
      executions.push({ rule_id: rule.id, rule_name: rule.name, result });

      // Log execution
      try {
        await supabase.from('soar_executions').insert({
          tenant_id: tenantId,
          rule_id:   rule.id,
          rule_name: rule.name,
          status:    result.success ? 'success' : 'failure',
          trigger:   result.trigger,
          actions_taken: result.actions || [],
          metadata:  result.metadata || {},
        });
      } catch (_) { /* soar_executions insert non-fatal */ }

    } catch (err) {
      console.warn(`[SOAR] Rule ${rule.name} failed: ${err.message}`);
      executions.push({ rule_id: rule.id, rule_name: rule.name, error: err.message });
    }
  }

  return executions;
}

async function executeRule(rule, tenantId) {
  const { trigger, conditions, actions } = rule;
  const result = { success: false, trigger: trigger?.type, actions: [], metadata: {} };

  // ── Evaluate trigger conditions ─────────────────────
  if (trigger?.type === 'ioc_risk_score') {
    const threshold = trigger.threshold || 70;
    const { data: matches } = await supabase
      .from('iocs')
      .select('id, value, type, risk_score')
      .eq('tenant_id', tenantId)
      .gte('risk_score', threshold)
      .gt('updated_at', new Date(Date.now() - 60 * 60000).toISOString()) // Last hour
      .limit(10);

    if (!matches?.length) return { ...result, reason: 'No matching IOCs' };
    result.metadata.matched_iocs = matches.length;

    // ── Execute actions ─────────────────────────────
    for (const action of (actions || [])) {
      if (action.type === 'create_alert') {
        for (const ioc of matches) {
          try {
            await supabase.from('alerts').insert({
              tenant_id:  tenantId,
              title:      action.title?.replace('{ioc}', ioc.value) || `High-risk IOC: ${ioc.value}`,
              description:action.description || `Risk score: ${ioc.risk_score}`,
              severity:   action.severity || 'high',
              status:     'open',
              type:       'indicator',
              ioc_value:  ioc.value,
              ioc_type:   ioc.type,
              source:     `SOAR Rule: ${rule.name}`,
            });
          } catch (_) { /* alert insert non-fatal */ }
          result.actions.push(`alert_created:${ioc.value}`);
        }
      }

      if (action.type === 'tag_ioc') {
        for (const ioc of matches) {
          const tag = action.tag || 'soar-flagged';
          try {
            await supabase.rpc('array_append_unique', {
              table_name: 'iocs',
              record_id:  ioc.id,
              column_name:'tags',
              value:       tag,
            });
          } catch (_rpcErr) {
            // Fallback: manual tag append
            try {
              const { data: existing } = await supabase.from('iocs').select('tags').eq('id', ioc.id).single();
              if (existing && !existing.tags?.includes(tag)) {
                await supabase.from('iocs').update({ tags: [...(existing.tags || []), tag] }).eq('id', ioc.id);
              }
            } catch (_) { /* tag update non-fatal */ }
          }
          result.actions.push(`tagged:${ioc.value}:${tag}`);
        }
      }

      if (action.type === 'send_webhook' && action.url) {
        try {
          const axios = require('axios');
          await axios.post(action.url, {
            rule: rule.name,
            tenant_id: tenantId,
            matches: matches.length,
            timestamp: new Date().toISOString(),
          }, { timeout: 5000 });
          result.actions.push('webhook_sent');
        } catch (webhookErr) {
          result.actions.push(`webhook_failed:${webhookErr.message}`);
        }
      }
    }

    result.success = true;
  }

  return result;
}

// ════════════════════════════════════════════════════════════
//  HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════

async function storeIOCMITRERelationships(tenantId, iocId, mitreTechniques) {
  for (const technique of mitreTechniques) {
    try {
      await supabase.from('ioc_relationships').insert({
        tenant_id:         tenantId,
        source_id:         iocId,
        source_type:       'ioc',
        target_id:         technique,
        target_type:       'mitre_technique',
        relationship_type: 'indicates',
        confidence:        60,
      });
    } catch (_) { /* duplicate relationship — ignore */ }
  }
}

function buildAlertTitle(ioc) {
  const type = ioc.type?.toUpperCase() || 'IOC';
  if (ioc.malware_family) {
    return `${ioc.malware_family} ${type} Detected: ${ioc.value.slice(0, 60)}`;
  }
  if (ioc.threat_actor) {
    return `${ioc.threat_actor} ${type} Indicator: ${ioc.value.slice(0, 60)}`;
  }
  const repMap = { malicious: 'Malicious', suspicious: 'Suspicious' };
  return `${repMap[ioc.reputation] || 'High-Risk'} ${type} Detected: ${ioc.value.slice(0, 60)}`;
}

function buildAlertDescription(ioc) {
  const lines = [
    `Indicator: ${ioc.value}`,
    `Type: ${ioc.type}`,
    `Risk Score: ${ioc.risk_score}/100`,
    `Reputation: ${ioc.reputation}`,
  ];
  if (ioc.threat_actor)   lines.push(`Threat Actor: ${ioc.threat_actor}`);
  if (ioc.malware_family) lines.push(`Malware Family: ${ioc.malware_family}`);
  if (ioc.country)        lines.push(`Origin Country: ${ioc.country}`);
  if (ioc.source)         lines.push(`Source: ${ioc.source}`);

  lines.push('');
  lines.push('Auto-generated by SOAR engine based on risk score threshold breach.');

  return lines.join('\n');
}

function mapIOCTypeToAlertType(iocType) {
  const map = {
    ip:          'network',
    domain:      'network',
    url:         'web',
    hash_sha256: 'malware',
    hash_md5:    'malware',
    hash_sha1:   'malware',
    email:       'phishing',
    cve:         'vulnerability',
  };
  return map[iocType] || 'indicator';
}

function _sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ════════════════════════════════════════════════════════════
//  PUBLIC API
// ════════════════════════════════════════════════════════════
module.exports = {
  runRules,
  autoEnrichNewIOCs,
  autoFlagHighRiskIOCs,
  autoCreateCriticalCases,
  runCustomRules,
};
