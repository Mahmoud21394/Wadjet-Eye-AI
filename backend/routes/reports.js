/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — SOC Investigation Report Routes v2.0
 *  FILE: backend/routes/reports.js
 *
 *  Endpoints:
 *    POST /api/reports/investigate     — Generate 10-section investigation report
 *    POST /api/reports/generate        — Generate custom report (legacy)
 *    GET  /api/reports                 — List reports
 *    GET  /api/reports/:id             — Get report detail
 *    DELETE /api/reports/:id           — Delete report
 *    GET  /api/reports/:id/export      — Export report as markdown/PDF
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const express = require('express');
const router  = express.Router();
const { supabase }     = require('../config/supabase');
const { verifyToken }  = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');

// SOC Investigation Engine
let socInvestigation;
try {
  socInvestigation = require('../services/soc-investigation');
} catch (err) {
  console.warn('[Reports] soc-investigation service not found:', err.message);
}

// AI caller (for AI-enhanced narratives)
let aiRouter;
const callAIForReport = async (messages) => {
  try {
    const axios = require('axios');
    const key = process.env.OPENAI_API_KEY || process.env.CLAUDE_API_KEY || process.env.GEMINI_API_KEY;
    if (!key) return null;

    if (process.env.OPENAI_API_KEY) {
      const r = await axios.post('https://api.openai.com/v1/chat/completions', {
        model: 'gpt-4o', messages, max_tokens: 2000, temperature: 0.3,
      }, {
        headers: { 'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
        timeout: 30000,
      });
      return r.data.choices[0].message.content;
    }
  } catch (_) {}
  return null;
};

/* ══════════════════════════════════════════════════════════
   POST /api/reports/investigate
   Generate a complete 10-section SOC investigation report
══════════════════════════════════════════════════════════ */
router.post('/investigate', verifyToken, asyncHandler(async (req, res) => {
  const {
    incidentId,
    title,
    alertIds  = [],     // alert IDs to include
    eventIds  = [],     // event IDs to include
    rawAlerts = [],     // directly-provided alert objects
    rawEvents = [],     // directly-provided event objects
    metadata  = {},
    useAI     = true,   // use AI to enhance narrative
  } = req.body;

  const tenantId = req.tenantId || req.user?.tenant_id;

  // Fetch alerts from DB
  let alerts = [...rawAlerts];
  if (alertIds.length > 0) {
    const { data: dbAlerts } = await supabase
      .from('alerts')
      .select('*')
      .in('id', alertIds)
      .eq('tenant_id', tenantId);
    if (dbAlerts) alerts = [...alerts, ...dbAlerts];
  }

  // Fallback: fetch recent alerts if none specified
  if (alerts.length === 0 && alertIds.length === 0 && rawAlerts.length === 0) {
    const { data: recentAlerts } = await supabase
      .from('alerts')
      .select('*')
      .eq('tenant_id', tenantId)
      .order('created_at', { ascending: false })
      .limit(20);
    if (recentAlerts) alerts = recentAlerts;
  }

  // Fetch events
  let events = [...rawEvents];
  if (eventIds.length > 0) {
    const { data: dbEvents } = await supabase
      .from('events')
      .select('*')
      .in('id', eventIds);
    if (dbEvents) events = [...events, ...dbEvents];
  }

  // Fetch related IOCs from DB
  let dbIOCs = [];
  try {
    const cveIds = alerts
      .map(a => a.cve_id || (a.title || '').match(/CVE-\d{4}-\d+/i)?.[0])
      .filter(Boolean);
    if (cveIds.length > 0) {
      metadata.cveIds = cveIds;
    }

    const { data: iocData } = await supabase
      .from('iocs')
      .select('value, type, reputation, risk_score, threat_actor, tags')
      .eq('tenant_id', tenantId)
      .in('reputation', ['malicious', 'suspicious'])
      .order('risk_score', { ascending: false })
      .limit(30);
    if (iocData) dbIOCs = iocData;
  } catch (_) {}

  // Convert IOC DB records to events for better extraction
  const iocEvents = dbIOCs.map(i => ({
    type:       'ioc',
    source_ip:  i.type === 'ip'     ? i.value : undefined,
    host:       i.type === 'domain' ? i.value : undefined,
    description: `IOC ${i.type}: ${i.value} [${i.reputation}] risk=${i.risk_score} actor=${i.threat_actor || 'unknown'}`,
    timestamp:  new Date().toISOString(),
    severity:   i.risk_score >= 80 ? 'critical' : i.risk_score >= 60 ? 'high' : 'medium',
  }));

  const allEvents = [...events, ...iocEvents];

  if (!socInvestigation) {
    return res.status(503).json({ error: 'SOC investigation engine not available.' });
  }

  // Generate the structured report
  const reportData = socInvestigation.generateInvestigationReport({
    incidentId: incidentId || `INC-${Date.now()}`,
    title:      title || 'Security Incident Investigation',
    alerts,
    events:     allEvents,
    metadata,
    analyst:    `${req.user?.name || 'Analyst'} (Wadjet-Eye AI)`,
  });

  // AI enhancement (add AI narrative if available)
  let aiNarrative = null;
  if (useAI && alerts.length > 0) {
    try {
      const alertSummary = alerts.slice(0, 10).map(a =>
        `[${a.severity || 'MEDIUM'}] ${a.title || 'Alert'}: ${a.description || ''}`.slice(0, 200)
      ).join('\n');

      const aiResponse = await callAIForReport([
        { role: 'system', content: 'You are a senior SOC analyst. Write concise, data-driven threat analysis.' },
        { role: 'user',   content: `Provide a 3-paragraph threat actor analysis and attack intent assessment based on these alerts:\n\n${alertSummary}\n\nFocus on: 1) Likely threat actor profile, 2) Attack objectives, 3) Recommended investigation priorities.` },
      ]);
      if (aiResponse) aiNarrative = aiResponse;
    } catch (_) {}
  }

  // Save report to DB
  let savedId = null;
  try {
    const { data: saved } = await supabase
      .from('reports')
      .insert({
        tenant_id:   tenantId,
        title:       reportData.title,
        type:        'investigation',
        incident_id: reportData.incidentId,
        severity:    reportData.severity,
        risk_score:  reportData.riskScore,
        content:     reportData.report,
        ai_narrative: aiNarrative,
        metadata:    {
          alertCount:    reportData.metadata.alertCount,
          eventCount:    reportData.metadata.eventCount,
          hostCount:     reportData.metadata.hostCount,
          techniques:    reportData.techniques,
          iocs:          reportData.iocs,
          sectionCount:  reportData.sectionCount,
        },
        created_by:  req.user?.id,
      })
      .select('id')
      .single();
    if (saved) savedId = saved.id;
  } catch (dbErr) {
    console.warn('[Reports] DB save failed:', dbErr.message);
  }

  // Audit log
  try {
    await supabase.from('audit_logs').insert({
      user_id:   req.user?.id,
      tenant_id: tenantId,
      action:    'GENERATE_INVESTIGATION_REPORT',
      resource:  'reports',
      details:   { incidentId: reportData.incidentId, severity: reportData.severity, riskScore: reportData.riskScore },
    });
  } catch (_) {}

  res.json({
    id:          savedId,
    incidentId:  reportData.incidentId,
    title:       reportData.title,
    severity:    reportData.severity,
    riskScore:   reportData.riskScore,
    techniques:  reportData.techniques,
    iocs:        reportData.iocs,
    report:      reportData.report,
    aiNarrative,
    sectionCount: reportData.sectionCount,
    metadata:    reportData.metadata,
    generatedAt: reportData.metadata.generatedAt,
  });
}));

/* ══════════════════════════════════════════════════════════
   POST /api/reports/generate — Legacy/general report generation
══════════════════════════════════════════════════════════ */
router.post('/generate', verifyToken, asyncHandler(async (req, res) => {
  const { type = 'threat-summary', period_hours = 24, options = {} } = req.body;
  const tenantId = req.tenantId || req.user?.tenant_id;

  const since = new Date(Date.now() - period_hours * 3600000).toISOString();

  let reportContent = '';
  let data = {};

  if (type === 'threat-summary') {
    const { data: alerts } = await supabase
      .from('alerts')
      .select('title, severity, type, status, mitre_technique, source_ip, created_at')
      .eq('tenant_id', tenantId)
      .gte('created_at', since)
      .order('created_at', { ascending: false })
      .limit(50);

    const { data: iocs } = await supabase
      .from('iocs')
      .select('value, type, reputation, risk_score, threat_actor')
      .eq('tenant_id', tenantId)
      .gte('risk_score', 50)
      .limit(30);

    data = { alerts: alerts || [], iocs: iocs || [], period_hours };

    const critical = (alerts || []).filter(a => a.severity === 'critical').length;
    const high     = (alerts || []).filter(a => a.severity === 'high').length;
    const uniqueTechniques = [...new Set((alerts || []).map(a => a.mitre_technique).filter(Boolean))];

    reportContent = `# Threat Intelligence Summary Report
**Period**: Last ${period_hours} hours
**Generated**: ${new Date().toISOString()}

## Alert Statistics
- **Total Alerts**: ${(alerts || []).length}
- **Critical**: ${critical}
- **High**: ${high}
- **MITRE Techniques**: ${uniqueTechniques.join(', ') || 'N/A'}

## Top IOCs
${(iocs || []).slice(0, 10).map(i => `- \`${i.value}\` (${i.type}) | Score: ${i.risk_score}/100 | Actor: ${i.threat_actor || 'Unknown'}`).join('\n') || '- No high-risk IOCs in this period'}

## Recent Critical Alerts
${(alerts || []).filter(a => a.severity === 'critical').slice(0, 5).map(a => `- [CRITICAL] ${a.title} | MITRE: ${a.mitre_technique || 'N/A'} | ${a.created_at}`).join('\n') || '- No critical alerts'}`;
  }

  // Save to DB
  let savedId = null;
  try {
    const { data: saved } = await supabase
      .from('reports')
      .insert({
        tenant_id:   tenantId,
        title:       `${type} - ${new Date().toLocaleDateString()}`,
        type:        type,
        content:     reportContent,
        metadata:    { period_hours, dataPoints: Object.keys(data).length },
        created_by:  req.user?.id,
      })
      .select('id').single();
    if (saved) savedId = saved.id;
  } catch (_) {}

  res.json({
    id:      savedId,
    type,
    report:  reportContent,
    data,
    generatedAt: new Date().toISOString(),
  });
}));

/* ══════════════════════════════════════════════════════════
   GET /api/reports — List reports
══════════════════════════════════════════════════════════ */
router.get('/', verifyToken, asyncHandler(async (req, res) => {
  const { type, page = 1, limit = 20 } = req.query;
  const tenantId = req.tenantId || req.user?.tenant_id;
  const offset   = (parseInt(page) - 1) * parseInt(limit);

  let q = supabase
    .from('reports')
    .select('id, title, type, incident_id, severity, risk_score, created_at, created_by, metadata', { count: 'exact' })
    .eq('tenant_id', tenantId)
    .order('created_at', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (type) q = q.eq('type', type);

  const { data, error, count } = await q;
  if (error) throw createError(500, error.message);

  res.json({
    reports:    data || [],
    total:      count || 0,
    page:       parseInt(page),
    limit:      parseInt(limit),
    totalPages: Math.ceil((count || 0) / parseInt(limit)),
  });
}));

/* ══════════════════════════════════════════════════════════
   GET /api/reports/:id — Get report detail
══════════════════════════════════════════════════════════ */
router.get('/:id', verifyToken, asyncHandler(async (req, res) => {
  const tenantId = req.tenantId || req.user?.tenant_id;
  const { data, error } = await supabase
    .from('reports')
    .select('*')
    .eq('id', req.params.id)
    .eq('tenant_id', tenantId)
    .single();

  if (error || !data) throw createError(404, 'Report not found');
  res.json(data);
}));

/* ══════════════════════════════════════════════════════════
   GET /api/reports/:id/export — Export report
══════════════════════════════════════════════════════════ */
router.get('/:id/export', verifyToken, asyncHandler(async (req, res) => {
  const { format = 'markdown' } = req.query;
  const tenantId = req.tenantId || req.user?.tenant_id;

  const { data, error } = await supabase
    .from('reports')
    .select('*')
    .eq('id', req.params.id)
    .eq('tenant_id', tenantId)
    .single();

  if (error || !data) throw createError(404, 'Report not found');

  const filename = `${data.incident_id || data.id}-report.${format === 'json' ? 'json' : 'md'}`;

  if (format === 'json') {
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/json');
    return res.json(data);
  }

  // Markdown export
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'text/markdown');
  res.send(data.content || '# Empty Report');
}));

/* ══════════════════════════════════════════════════════════
   DELETE /api/reports/:id
══════════════════════════════════════════════════════════ */
router.delete('/:id', verifyToken, asyncHandler(async (req, res) => {
  const tenantId = req.tenantId || req.user?.tenant_id;
  const { error } = await supabase
    .from('reports')
    .delete()
    .eq('id', req.params.id)
    .eq('tenant_id', tenantId);

  if (error) throw createError(500, error.message);
  res.json({ success: true, message: 'Report deleted.' });
}));

module.exports = router;
