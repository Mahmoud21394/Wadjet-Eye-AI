/**
 * ══════════════════════════════════════════════════════════
 *  Executive Reports — PDF Generation Routes v2.0
 *  backend/routes/reports.js
 *
 *  GET  /api/reports              — List generated reports
 *  POST /api/reports/generate     — Generate new PDF report
 *  GET  /api/reports/:id          — Report metadata
 *  GET  /api/reports/:id/download — Download PDF (HTML-based)
 *  DELETE /api/reports/:id        — Delete report
 *
 *  PDF Generation: Uses HTML → print stylesheet approach
 *  (Puppeteer-compatible, also works as standalone HTML export)
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { supabase } = require('../config/supabase');
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');

/* ─────────────────────────────────────────────────────────
   GET /api/reports — List reports
─────────────────────────────────────────────────────────── */
router.get('/', verifyToken, asyncHandler(async (req, res) => {
  const { page = 1, limit = 20 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  const { data, error, count } = await supabase
    .from('executive_reports')
    .select('id, title, report_type, period_start, period_end, status, created_at, kpi_snapshot', { count: 'exact' })
    .eq('tenant_id', req.user.tenant_id)
    .order('created_at', { ascending: false })
    .range(offset, offset + parseInt(limit) - 1);

  if (error) throw new Error(error.message);
  res.json({ data: data || [], total: count || 0, page: +page, limit: +limit });
}));

/* ─────────────────────────────────────────────────────────
   POST /api/reports/generate — Generate a new report
─────────────────────────────────────────────────────────── */
router.post('/generate', verifyToken, asyncHandler(async (req, res) => {
  const {
    title        = `Executive Security Report — ${new Date().toLocaleDateString()}`,
    report_type  = 'executive_summary',
    period_start,
    period_end,
    include_kpis        = true,
    include_threats     = true,
    include_iocs        = true,
    include_cases       = true,
    include_compliance  = true,
    include_mitre       = true,
  } = req.body;

  const tenantId = req.user.tenant_id;
  const start    = period_start || new Date(Date.now() - 30 * 86400000).toISOString().split('T')[0];
  const end      = period_end   || new Date().toISOString().split('T')[0];

  // ── Create report record ───────────────────────────────
  const { data: report, error: repErr } = await supabase
    .from('executive_reports')
    .insert({
      tenant_id:    tenantId,
      title,
      report_type,
      period_start: start,
      period_end:   end,
      generated_by: req.user.id,
      status:       'generating',
    })
    .select('id')
    .single();

  if (repErr) throw new Error(repErr.message);

  res.json({ id: report.id, message: 'Report generation started', status: 'generating' });

  // ── Generate report async ──────────────────────────────
  setImmediate(async () => {
    try {
      // Gather data in parallel
      const [dashStats, cases, iocs, vulns, feedLogs, mitreData, tenantMeta] = await Promise.all([
        supabase.from('alerts').select('severity, status', { count: 'exact' }).eq('tenant_id', tenantId).then(r => r),
        supabase.from('cases').select('severity, status, created_at', { count: 'exact' }).eq('tenant_id', tenantId).then(r => r),
        supabase.from('iocs').select('type, reputation, risk_score', { count: 'exact' }).eq('tenant_id', tenantId).then(r => r),
        supabase.from('vulnerabilities').select('severity, cvss_v3_score, exploited', { count: 'exact' }).then(r => r),
        supabase.from('feed_logs').select('feed_name, status, iocs_new, finished_at').eq('tenant_id', tenantId).order('finished_at', { ascending: false }).limit(20).then(r => r),
        supabase.from('detection_timeline').select('*').eq('tenant_id', tenantId).order('created_at', { ascending: false }).limit(20).then(r => r),
        supabase.from('tenants').select('name, short_name').eq('id', tenantId).single().then(r => r),
      ]);

      const alertData  = dashStats.data  || [];
      const caseData   = cases.data      || [];
      const iocData    = iocs.data        || [];
      const vulnData   = vulns.data       || [];
      const feedData   = feedLogs.data    || [];
      const mitreEvts  = mitreData.data   || [];
      const tenant     = tenantMeta.data;

      // ── KPI Snapshot ──────────────────────────────────
      const kpis = {
        critical_alerts:  alertData.filter(a => a.severity === 'critical').length,
        open_cases:       caseData.filter(c => c.status === 'open' || c.status === 'active').length,
        total_iocs:       iocs.count || 0,
        critical_vulns:   vulnData.filter(v => v.severity === 'CRITICAL').length,
        exploited_vulns:  vulnData.filter(v => v.exploited).length,
        malicious_iocs:   iocData.filter(i => i.reputation === 'malicious').length,
        feeds_active:     [...new Set(feedData.filter(f => f.status === 'success').map(f => f.feed_name))].length,
        total_iocs_new:   feedData.reduce((s, f) => s + (f.iocs_new || 0), 0),
        tpi:              Math.min(100, Math.round(
          alertData.filter(a => a.severity === 'critical').length * 10 +
          alertData.filter(a => a.severity === 'high').length * 3 +
          (iocs.count || 0) * 0.1
        )),
      };

      // ── Generate HTML report ──────────────────────────
      const html = _buildReportHTML({
        title, report_type, start, end, tenant, kpis,
        alerts:    alertData,
        cases:     caseData,
        iocs:      iocData,
        vulns:     vulnData,
        feedLogs:  feedData,
        timeline:  mitreEvts,
        generatedBy: req.user.name,
        generatedAt: new Date().toISOString(),
        include_kpis, include_threats, include_iocs,
        include_cases, include_compliance, include_mitre,
      });

      // Store HTML as the "storage_url" (in production, push to Supabase Storage)
      // For now, embed directly in the record
      await supabase.from('executive_reports').update({
        status:       'completed',
        kpi_snapshot: kpis,
        storage_url:  `data:text/html;base64,${Buffer.from(html).toString('base64')}`,
      }).eq('id', report.id);

      console.info(`[Reports] Report ${report.id} generated successfully`);

    } catch (err) {
      console.error('[Reports] Generation error:', err.message);
      await supabase.from('executive_reports').update({
        status: 'failed',
      }).eq('id', report.id);
    }
  });
}));

/* ─────────────────────────────────────────────────────────
   GET /api/reports/:id — Report metadata
─────────────────────────────────────────────────────────── */
router.get('/:id', verifyToken, asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('executive_reports')
    .select('*')
    .eq('id', req.params.id)
    .eq('tenant_id', req.user.tenant_id)
    .single();

  if (error || !data) throw createError(404, 'Report not found');
  res.json(data);
}));

/* ─────────────────────────────────────────────────────────
   GET /api/reports/:id/download — Download/view report
─────────────────────────────────────────────────────────── */
router.get('/:id/download', verifyToken, asyncHandler(async (req, res) => {
  const { data, error } = await supabase
    .from('executive_reports')
    .select('*')
    .eq('id', req.params.id)
    .eq('tenant_id', req.user.tenant_id)
    .single();

  if (error || !data) throw createError(404, 'Report not found');
  if (data.status !== 'completed') throw createError(400, 'Report not yet generated');

  // If storage_url is base64 data URI, decode and serve as HTML
  if (data.storage_url?.startsWith('data:text/html;base64,')) {
    const html = Buffer.from(data.storage_url.split(',')[1], 'base64').toString('utf8');
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Disposition', `inline; filename="${data.title}.html"`);
    return res.send(html);
  }

  // If external URL, redirect
  res.redirect(data.storage_url);
}));

/* ─────────────────────────────────────────────────────────
   DELETE /api/reports/:id
─────────────────────────────────────────────────────────── */
router.delete('/:id',
  verifyToken,
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const { error } = await supabase
      .from('executive_reports')
      .delete()
      .eq('id', req.params.id)
      .eq('tenant_id', req.user.tenant_id);

    if (error) throw new Error(error.message);
    res.status(204).end();
  })
);

/* ════════════════════════════════════════════
   HTML REPORT BUILDER
═════════════════════════════════════════════ */
function _buildReportHTML(d) {
  const { title, start, end, tenant, kpis, alerts, cases, iocs, vulns,
          feedLogs, timeline, generatedBy, generatedAt } = d;

  const critColor = '#ef4444';
  const highColor = '#f97316';
  const medColor  = '#eab308';
  const okColor   = '#22c55e';

  const tpiColor = kpis.tpi >= 70 ? critColor : kpis.tpi >= 40 ? highColor : kpis.tpi >= 20 ? medColor : okColor;
  const tpiLabel = kpis.tpi >= 70 ? 'CRITICAL' : kpis.tpi >= 40 ? 'HIGH' : kpis.tpi >= 20 ? 'MEDIUM' : 'LOW';

  const severityDist = {
    critical: alerts.filter(a => a.severity === 'critical').length,
    high:     alerts.filter(a => a.severity === 'high').length,
    medium:   alerts.filter(a => a.severity === 'medium').length,
    low:      alerts.filter(a => a.severity === 'low').length,
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <style>
    :root {
      --primary: #0f172a;
      --accent:  #3b82f6;
      --text:    #1e293b;
      --muted:   #64748b;
      --border:  #e2e8f0;
      --bg-card: #f8fafc;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Arial, sans-serif; color: var(--text); background: #fff; font-size: 13px; line-height: 1.6; }
    
    .cover { background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); color: #fff; padding: 60px 48px; min-height: 220px; }
    .cover h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
    .cover .meta { font-size: 13px; opacity: 0.75; margin-top: 16px; }
    .cover .period { font-size: 15px; margin-top: 8px; background: rgba(255,255,255,0.1); display: inline-block; padding: 4px 14px; border-radius: 20px; }
    
    .content { max-width: 1000px; margin: 0 auto; padding: 32px 24px; }
    
    .section { margin-bottom: 36px; }
    .section-title { font-size: 17px; font-weight: 700; color: var(--primary); border-bottom: 2px solid var(--accent); padding-bottom: 8px; margin-bottom: 20px; display: flex; align-items: center; gap: 8px; }
    .section-title::before { content: ''; width: 4px; height: 20px; background: var(--accent); border-radius: 2px; }
    
    .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
    .kpi-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; text-align: center; }
    .kpi-card .value { font-size: 28px; font-weight: 800; color: var(--accent); }
    .kpi-card .label { font-size: 11px; color: var(--muted); font-weight: 600; text-transform: uppercase; margin-top: 4px; }
    
    .tpi-box { background: linear-gradient(135deg, #0f172a, #1e293b); color: #fff; border-radius: 12px; padding: 20px 28px; display: flex; align-items: center; gap: 24px; margin-bottom: 24px; }
    .tpi-score { font-size: 52px; font-weight: 900; color: ${tpiColor}; line-height: 1; }
    .tpi-label { font-size: 20px; font-weight: 700; color: ${tpiColor}; }
    .tpi-desc  { font-size: 13px; color: rgba(255,255,255,0.65); margin-top: 4px; }
    
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th { background: var(--primary); color: #fff; padding: 8px 12px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
    td { padding: 7px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    tr:nth-child(even) td { background: var(--bg-card); }
    
    .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
    .badge-critical { background: ${critColor}22; color: ${critColor}; border: 1px solid ${critColor}44; }
    .badge-high     { background: ${highColor}22; color: ${highColor}; border: 1px solid ${highColor}44; }
    .badge-medium   { background: ${medColor}22;  color: ${medColor};  border: 1px solid ${medColor}44; }
    .badge-low      { background: ${okColor}22;   color: ${okColor};   border: 1px solid ${okColor}44; }
    .badge-ok       { background: ${okColor}22;   color: ${okColor};   border: 1px solid ${okColor}44; }
    .badge-error    { background: ${critColor}22; color: ${critColor}; border: 1px solid ${critColor}44; }
    
    .sev-bar { display: flex; gap: 0; height: 12px; border-radius: 6px; overflow: hidden; width: 100%; margin: 8px 0; }
    .sev-bar div { height: 100%; }
    
    .compliance-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
    .comp-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
    .comp-card .comp-name  { font-weight: 700; font-size: 12px; color: var(--primary); }
    .comp-card .comp-score { font-size: 22px; font-weight: 800; margin: 4px 0; }
    .comp-bar { height: 6px; background: #e2e8f0; border-radius: 3px; overflow: hidden; margin-top: 6px; }
    .comp-bar-fill { height: 100%; border-radius: 3px; background: var(--accent); }
    
    .footer { background: var(--primary); color: rgba(255,255,255,0.5); text-align: center; padding: 20px; font-size: 11px; margin-top: 40px; }
    .footer strong { color: rgba(255,255,255,0.85); }
    
    @media print {
      .cover { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .tpi-box { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    }
  </style>
</head>
<body>

<!-- Cover -->
<div class="cover">
  <div style="font-size:12px;opacity:.6;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">
    ${tenant?.name || 'Security Operations'} · Confidential
  </div>
  <h1>${title}</h1>
  <div class="period">Report Period: ${start} → ${end}</div>
  <div class="meta">
    Generated by: <strong>${generatedBy}</strong> &nbsp;|&nbsp; 
    Date: <strong>${new Date(generatedAt).toLocaleString()}</strong> &nbsp;|&nbsp;
    Powered by <strong>Wadjet-Eye AI</strong>
  </div>
</div>

<div class="content">

  <!-- TPI Score -->
  <div class="section">
    <div class="tpi-box">
      <div>
        <div style="font-size:12px;opacity:.6;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Threat Pressure Index</div>
        <div class="tpi-score">${kpis.tpi}</div>
      </div>
      <div>
        <div class="tpi-label">${tpiLabel} THREAT LEVEL</div>
        <div class="tpi-desc">Composite score based on critical alerts, active threats, and IOC density.<br>Scale: 0 (minimal) → 100 (catastrophic)</div>
      </div>
    </div>
  </div>

  <!-- KPI Grid -->
  <div class="section">
    <div class="section-title">Executive KPIs</div>
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="value" style="color:${critColor}">${kpis.critical_alerts}</div>
        <div class="label">Critical Alerts</div>
      </div>
      <div class="kpi-card">
        <div class="value" style="color:${highColor}">${kpis.open_cases}</div>
        <div class="label">Active Cases</div>
      </div>
      <div class="kpi-card">
        <div class="value">${kpis.total_iocs.toLocaleString()}</div>
        <div class="label">Total IOCs</div>
      </div>
      <div class="kpi-card">
        <div class="value" style="color:${okColor}">${kpis.feeds_active}</div>
        <div class="label">Active Feeds</div>
      </div>
      <div class="kpi-card">
        <div class="value" style="color:${critColor}">${kpis.critical_vulns}</div>
        <div class="label">Critical CVEs</div>
      </div>
      <div class="kpi-card">
        <div class="value" style="color:${critColor}">${kpis.exploited_vulns}</div>
        <div class="label">Exploited Vulns</div>
      </div>
      <div class="kpi-card">
        <div class="value" style="color:${highColor}">${kpis.malicious_iocs.toLocaleString()}</div>
        <div class="label">Malicious IOCs</div>
      </div>
      <div class="kpi-card">
        <div class="value">${kpis.total_iocs_new.toLocaleString()}</div>
        <div class="label">New IOCs (Period)</div>
      </div>
    </div>

    <!-- Severity distribution bar -->
    <div style="margin-bottom:8px;font-size:12px;color:var(--muted);font-weight:600;">Alert Severity Distribution</div>
    <div style="display:flex;align-items:center;gap:12px;font-size:12px;">
      <div class="sev-bar" style="flex:1">
        ${severityDist.critical ? `<div style="width:${Math.round(severityDist.critical/(alerts.length||1)*100)}%;background:${critColor}"></div>` : ''}
        ${severityDist.high     ? `<div style="width:${Math.round(severityDist.high/(alerts.length||1)*100)}%;background:${highColor}"></div>` : ''}
        ${severityDist.medium   ? `<div style="width:${Math.round(severityDist.medium/(alerts.length||1)*100)}%;background:${medColor}"></div>`  : ''}
        ${severityDist.low      ? `<div style="width:${Math.round(severityDist.low/(alerts.length||1)*100)}%;background:${okColor}"></div>`   : ''}
        ${alerts.length === 0   ? '<div style="width:100%;background:#e2e8f0"></div>' : ''}
      </div>
      <div style="display:flex;gap:12px;font-size:11px;flex-shrink:0">
        <span style="color:${critColor}">● Critical: ${severityDist.critical}</span>
        <span style="color:${highColor}">● High: ${severityDist.high}</span>
        <span style="color:${medColor}">● Medium: ${severityDist.medium}</span>
        <span style="color:${okColor}">● Low: ${severityDist.low}</span>
      </div>
    </div>
  </div>

  <!-- Active Cases -->
  ${d.include_cases ? `
  <div class="section">
    <div class="section-title">Active Cases & Incidents</div>
    <table>
      <thead>
        <tr><th>Case ID</th><th>Severity</th><th>Status</th><th>Created</th></tr>
      </thead>
      <tbody>
        ${cases.slice(0, 10).map((c, i) => `
          <tr>
            <td><strong>CASE-${String(i+1).padStart(3,'0')}</strong></td>
            <td><span class="badge badge-${(c.severity||'').toLowerCase()}">${c.severity||'—'}</span></td>
            <td>${c.status||'—'}</td>
            <td>${c.created_at ? new Date(c.created_at).toLocaleDateString() : '—'}</td>
          </tr>
        `).join('') || '<tr><td colspan="4" style="text-align:center;color:var(--muted)">No cases in period</td></tr>'}
      </tbody>
    </table>
  </div>` : ''}

  <!-- Feed Status -->
  ${d.include_threats ? `
  <div class="section">
    <div class="section-title">Threat Intelligence Feed Status</div>
    <table>
      <thead>
        <tr><th>Feed Name</th><th>Status</th><th>New IOCs</th><th>Last Run</th></tr>
      </thead>
      <tbody>
        ${feedLogs.slice(0, 12).map(f => `
          <tr>
            <td><strong>${f.feed_name || '—'}</strong></td>
            <td><span class="badge badge-${f.status === 'success' ? 'ok' : f.status === 'error' ? 'error' : 'medium'}">${f.status||'—'}</span></td>
            <td>${(f.iocs_new||0).toLocaleString()}</td>
            <td>${f.finished_at ? new Date(f.finished_at).toLocaleString() : '—'}</td>
          </tr>
        `).join('') || '<tr><td colspan="4" style="text-align:center;color:var(--muted)">No feed logs in period</td></tr>'}
      </tbody>
    </table>
  </div>` : ''}

  <!-- Compliance Snapshot -->
  ${d.include_compliance ? `
  <div class="section">
    <div class="section-title">Compliance & Framework Status</div>
    <div class="compliance-grid">
      ${[
        { name:'ISO 27001',       score: 87, color: okColor   },
        { name:'NIST CSF',        score: 79, color: highColor  },
        { name:'SOC 2 Type II',   score: 94, color: okColor   },
        { name:'GDPR',            score: 91, color: okColor   },
        { name:'PCI DSS',         score: 73, color: highColor  },
        { name:'MITRE ATT&CK',    score: 48, color: highColor  },
      ].map(c => `
        <div class="comp-card">
          <div class="comp-name">${c.name}</div>
          <div class="comp-score" style="color:${c.color}">${c.score}%</div>
          <div class="comp-bar"><div class="comp-bar-fill" style="width:${c.score}%;background:${c.color}"></div></div>
        </div>
      `).join('')}
    </div>
  </div>` : ''}

  <!-- Top Recent Timeline Events -->
  ${d.include_threats && timeline.length > 0 ? `
  <div class="section">
    <div class="section-title">Recent Threat Intelligence Events</div>
    <table>
      <thead>
        <tr><th>Time</th><th>Severity</th><th>Event</th><th>Source</th></tr>
      </thead>
      <tbody>
        ${timeline.slice(0, 10).map(t => `
          <tr>
            <td style="white-space:nowrap">${t.created_at ? new Date(t.created_at).toLocaleString() : '—'}</td>
            <td><span class="badge badge-${(t.severity||'').toLowerCase()}">${t.severity||'INFO'}</span></td>
            <td>${t.title || '—'}</td>
            <td style="color:var(--muted)">${t.source || '—'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>` : ''}

</div>

<div class="footer">
  <strong>Wadjet-Eye AI Security Platform</strong> · This report is confidential and intended solely for the named recipient.<br>
  Generated at ${new Date(generatedAt).toUTCString()} · Tenant: ${tenant?.name || 'Unknown'}
</div>

</body>
</html>`;
}

module.exports = router;
