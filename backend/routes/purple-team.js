/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Purple Team & Adversary Simulation Routes (Phase 7)
 *  backend/routes/purple-team.js
 *
 *  GET  /api/purple-team/scenarios           — List simulation scenarios
 *  POST /api/purple-team/sessions            — Start adversary simulation
 *  GET  /api/purple-team/sessions/:id        — Get session status
 *  GET  /api/purple-team/sessions/:id/results — Get simulation results
 *  DELETE /api/purple-team/sessions/:id      — Stop/cancel simulation
 *  GET  /api/purple-team/coverage            — ATT&CK detection coverage
 *  POST /api/purple-team/coverage/test       — Test specific technique detection
 *  GET  /api/purple-team/gap-analysis        — Detection gap analysis
 *  POST /api/purple-team/caldera/execute     — Trigger Caldera ability
 *  GET  /api/purple-team/caldera/operations  — List Caldera operations
 *  GET  /api/purple-team/results/history     — Historical test results
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const router = require('express').Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler, createError } = require('../middleware/errorHandler');
const adversarySim = require('../services/purple-team/adversary-sim');
const { supabase }  = require('../config/supabase');
const { z }         = require('zod');

// All purple team routes require analyst or higher
router.use(verifyToken);

// ── Schemas ───────────────────────────────────────────────────────
const StartSessionSchema = z.object({
  scenario_id:  z.string().min(1).max(100),
  target_hosts: z.array(z.string().max(253)).min(1).max(20).optional(),
  auto_detect:  z.boolean().default(true),
  notify_soc:   z.boolean().default(false),
  dry_run:      z.boolean().default(true),  // Default safe: dry_run = no actual execution
  timeout_ms:   z.number().int().min(10000).max(3600000).default(300000),
});

const TestTechniqueSchema = z.object({
  technique_id:  z.string().regex(/^T\d{4}(\.\d{3})?$/, 'Invalid ATT&CK technique ID'),
  target_host:   z.string().max(253).optional(),
  timeout_s:     z.number().int().min(5).max(300).default(30),
});

const CalderaExecuteSchema = z.object({
  ability_id:    z.string().uuid(),
  agent_paw:     z.string().max(20),
  timeout_s:     z.number().int().min(5).max(600).default(60),
});

// ── Static scenario catalog ───────────────────────────────────────
const SCENARIO_CATALOG = [
  {
    id:           'apt29-solorigate',
    name:         'APT29 — SolarWinds Solorigate',
    description:  'Simulates APT29 SolarWinds supply-chain attack TTPs: DLL hijacking, token manipulation, lateral movement via LDAP',
    difficulty:   'CRITICAL',
    actor:        'APT29 (Cozy Bear)',
    phases:       9,
    duration_min: 45,
    mitre_tactics: ['initial-access','persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','exfiltration'],
    techniques:   ['T1195.002','T1078','T1134','T1036','T1003.001','T1021.002'],
    caldera_profile: 'apt29-solorigate',
    safe:         false,
  },
  {
    id:           'lazarus-financial',
    name:         'Lazarus Group — Financial Sector Attack',
    description:  'Simulates Lazarus Group SWIFT heist TTPs: spear-phishing, PowerShell, custom malware, destructive wiper',
    difficulty:   'HIGH',
    actor:        'Lazarus Group (DPRK)',
    phases:       7,
    duration_min: 30,
    mitre_tactics: ['initial-access','execution','persistence','lateral-movement','collection','exfiltration','impact'],
    techniques:   ['T1566.001','T1059.001','T1055','T1560','T1485'],
    caldera_profile: 'lazarus-financial',
    safe:         false,
  },
  {
    id:           'lockbit-ransomware',
    name:         'LockBit 3.0 Ransomware Chain',
    description:  'Full LockBit ransomware kill chain: access broker → privilege escalation → AD compromise → ransomware deployment',
    difficulty:   'HIGH',
    actor:        'LockBit RaaS',
    phases:       6,
    duration_min: 25,
    mitre_tactics: ['initial-access','execution','privilege-escalation','defense-evasion','lateral-movement','impact'],
    techniques:   ['T1190','T1078.002','T1059.003','T1112','T1486'],
    caldera_profile: 'lockbit-3',
    safe:         false,
  },
  {
    id:           'apt41-espionage',
    name:         'APT41 — Dual Espionage + Financial',
    description:  'APT41 combined nation-state espionage and financial crime: web shell exploitation, supply-chain, data theft',
    difficulty:   'CRITICAL',
    actor:        'APT41 (China)',
    phases:       10,
    duration_min: 60,
    mitre_tactics: ['initial-access','execution','persistence','privilege-escalation','discovery','lateral-movement','collection','exfiltration'],
    techniques:   ['T1190','T1505.003','T1071.001','T1041'],
    caldera_profile: 'apt41-espionage',
    safe:         false,
  },
  {
    id:           'fin7-retail',
    name:         'FIN7 — Retail POS Intrusion',
    description:  'FIN7 retail intrusion: phishing → backdoor → POS malware → exfiltration via DNS tunneling',
    difficulty:   'HIGH',
    actor:        'FIN7',
    phases:       5,
    duration_min: 20,
    mitre_tactics: ['initial-access','execution','persistence','collection','exfiltration'],
    techniques:   ['T1566.002','T1059.005','T1547.001','T1056.001','T1048.003'],
    caldera_profile: 'fin7-retail',
    safe:         false,
  },
  {
    id:           'volt-typhoon-infra',
    name:         'Volt Typhoon — Critical Infrastructure',
    description:  'Volt Typhoon living-off-the-land TTPs targeting critical infrastructure: LOLBins, SOHO router compromise, tunneling',
    difficulty:   'CRITICAL',
    actor:        'Volt Typhoon (China)',
    phases:       8,
    duration_min: 40,
    mitre_tactics: ['initial-access','discovery','lateral-movement','collection','command-and-control'],
    techniques:   ['T1133','T1003.003','T1021.004','T1090.001','T1083'],
    caldera_profile: 'volt-typhoon',
    safe:         false,
  },
  {
    id:           'insider-threat-basic',
    name:         'Insider Threat — Data Exfiltration',
    description:  'Malicious insider: privileged access abuse, bulk download, USB exfiltration, log tampering',
    difficulty:   'MEDIUM',
    actor:        'Malicious Insider',
    phases:       4,
    duration_min: 15,
    mitre_tactics: ['collection','exfiltration','defense-evasion'],
    techniques:   ['T1039','T1052.001','T1070.001'],
    caldera_profile: 'insider-threat',
    safe:         true,
  },
  {
    id:           'detection-validation',
    name:         'Detection Rule Validation Suite',
    description:  'Safe, non-destructive suite to validate all detection rules are firing correctly. No actual payloads executed.',
    difficulty:   'LOW',
    actor:        'Internal',
    phases:       3,
    duration_min: 10,
    mitre_tactics: ['all'],
    techniques:   ['all-enabled-rules'],
    caldera_profile: null,
    safe:         true,
  },
];

// ══════════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════════

/**
 * GET /api/purple-team/scenarios
 */
router.get('/scenarios', asyncHandler(async (req, res) => {
  const difficulty = req.query.difficulty;
  const safe       = req.query.safe === 'true';

  let scenarios = SCENARIO_CATALOG;
  if (difficulty) scenarios = scenarios.filter(s => s.difficulty === difficulty.toUpperCase());
  if (safe)       scenarios = scenarios.filter(s => s.safe === true);

  res.json({
    success:  true,
    count:    scenarios.length,
    scenarios,
  });
}));

/**
 * GET /api/purple-team/scenarios/:id
 */
router.get('/scenarios/:id', asyncHandler(async (req, res) => {
  const scenario = SCENARIO_CATALOG.find(s => s.id === req.params.id);
  if (!scenario) throw createError(404, `Scenario '${req.params.id}' not found`);
  res.json({ success: true, scenario });
}));

/**
 * POST /api/purple-team/sessions
 * Start an adversary simulation session
 */
router.post(
  '/sessions',
  requireRole(['TEAM_LEAD', 'ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const parsed = StartSessionSchema.safeParse(req.body);
    if (!parsed.success) throw createError(400, parsed.error.message);

    const params   = parsed.data;
    const scenario = SCENARIO_CATALOG.find(s => s.id === params.scenario_id);
    if (!scenario) throw createError(404, `Scenario '${params.scenario_id}' not found`);

    // Safety gate: non-safe scenarios require explicit confirmation
    if (!scenario.safe && !params.dry_run) {
      throw createError(422, [
        'Non-safe scenario with dry_run=false requires explicit approval.',
        'Set dry_run=true for safe simulation, or obtain approval from SUPER_ADMIN.',
      ].join(' '));
    }

    const session = await adversarySim.startSession({
      ...params,
      scenario,
      initiated_by: req.user?.id,
      tenant_id:    req.tenantId,
    });

    // Audit log
    const { auditLog } = require('../middleware/audit');
    req.auditAction  = 'PURPLE_TEAM_SESSION_START';
    req.auditDetails = { session_id: session.id, scenario_id: params.scenario_id, dry_run: params.dry_run };

    res.status(202).json({
      success:    true,
      session_id: session.id,
      scenario:   scenario.name,
      dry_run:    params.dry_run,
      status:     session.status,
      started_at: session.started_at,
      message:    params.dry_run
        ? 'Dry-run simulation started — no actual payloads will execute'
        : 'Live simulation started — SOC team has been notified',
    });
  })
);

/**
 * GET /api/purple-team/sessions/:id
 */
router.get('/sessions/:id', asyncHandler(async (req, res) => {
  const session = await adversarySim.getSession(req.params.id, req.tenantId);
  if (!session) throw createError(404, 'Session not found');
  res.json({ success: true, session });
}));

/**
 * GET /api/purple-team/sessions/:id/results
 */
router.get('/sessions/:id/results', asyncHandler(async (req, res) => {
  const results = await adversarySim.getSessionResults(req.params.id, req.tenantId);
  if (!results) throw createError(404, 'Session not found');

  res.json({
    success: true,
    data:    results,
  });
}));

/**
 * DELETE /api/purple-team/sessions/:id
 */
router.delete(
  '/sessions/:id',
  requireRole(['TEAM_LEAD', 'ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    await adversarySim.stopSession(req.params.id, req.tenantId);
    res.json({ success: true, message: 'Session stopped' });
  })
);

/**
 * GET /api/purple-team/coverage
 * ATT&CK technique detection coverage from enabled rules
 */
router.get('/coverage', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;

  const { data: rules, error } = await supabase
    .from('detection_rules')
    .select('rule_id, name, mitre_tactic, mitre_technique, severity, enabled, tp_count, fp_count, trigger_count')
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .eq('enabled', true);

  if (error) throw createError(500, error.message);

  // Build coverage matrix
  const coverage = {};
  const tactics  = new Set();

  for (const rule of (rules || [])) {
    const tactic    = rule.mitre_tactic    || 'unknown';
    const technique = rule.mitre_technique || 'unknown';
    tactics.add(tactic);

    if (!coverage[tactic]) coverage[tactic] = {};
    if (!coverage[tactic][technique]) {
      coverage[tactic][technique] = { rules: [], covered: false, rule_count: 0 };
    }
    coverage[tactic][technique].rules.push({
      rule_id:       rule.rule_id,
      name:          rule.name,
      severity:      rule.severity,
      trigger_count: rule.trigger_count,
      tp_rate:       rule.tp_count / Math.max(rule.trigger_count, 1),
    });
    coverage[tactic][technique].covered    = true;
    coverage[tactic][technique].rule_count++;
  }

  // ATT&CK Enterprise matrix: 14 tactics
  const ALL_TACTICS = [
    'reconnaissance','resource-development','initial-access','execution',
    'persistence','privilege-escalation','defense-evasion','credential-access',
    'discovery','lateral-movement','collection','command-and-control',
    'exfiltration','impact',
  ];

  const coveredTactics   = ALL_TACTICS.filter(t => coverage[t]);
  const uncoveredTactics = ALL_TACTICS.filter(t => !coverage[t]);

  const totalRules       = (rules || []).length;
  const coveredTacticPct = Math.round((coveredTactics.length / ALL_TACTICS.length) * 100);

  res.json({
    success: true,
    summary: {
      total_rules:     totalRules,
      tactics_covered: coveredTactics.length,
      tactics_total:   ALL_TACTICS.length,
      tactic_coverage_pct: coveredTacticPct,
      coverage_grade:  coverageGrade(coveredTacticPct),
    },
    coverage_matrix:   coverage,
    covered_tactics:   coveredTactics,
    uncovered_tactics: uncoveredTactics,
  });
}));

/**
 * POST /api/purple-team/coverage/test
 * Test if a specific ATT&CK technique has active detections
 */
router.post('/coverage/test', asyncHandler(async (req, res) => {
  const parsed = TestTechniqueSchema.safeParse(req.body);
  if (!parsed.success) throw createError(400, parsed.error.message);

  const { technique_id, target_host, timeout_s } = parsed.data;
  const tenantId = req.tenantId;

  // Check rule coverage
  const { data: rules } = await supabase
    .from('detection_rules')
    .select('rule_id, name, severity, threshold, tp_count, fp_count, trigger_count')
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .eq('mitre_technique', technique_id)
    .eq('enabled', true);

  const hasRules = (rules || []).length > 0;

  // Check recent alert coverage
  const since = new Date(Date.now() - 30 * 24 * 3600000).toISOString();
  const { count: alertCount } = await supabase
    .from('alerts')
    .select('id', { count: 'exact', head: true })
    .eq('tenant_id', tenantId)
    .eq('mitre_technique', technique_id)
    .gte('created_at', since);

  const result = await adversarySim.testTechniqueDetection({
    technique_id,
    target_host,
    timeout_s,
    tenant_id: tenantId,
  });

  res.json({
    success:        true,
    technique_id,
    has_rules:      hasRules,
    rule_count:     (rules || []).length,
    recent_alerts:  alertCount || 0,
    rules:          rules || [],
    detection_test: result,
    coverage_status: hasRules ? (alertCount > 0 ? 'ACTIVE' : 'RULES_NO_ALERTS') : 'GAP',
  });
}));

/**
 * GET /api/purple-team/gap-analysis
 * Identify ATT&CK techniques with no detection coverage
 */
router.get('/gap-analysis', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;

  const { data: rules } = await supabase
    .from('detection_rules')
    .select('mitre_tactic, mitre_technique, severity')
    .or(`tenant_id.eq.${tenantId},tenant_id.is.null`)
    .eq('enabled', true)
    .not('mitre_technique', 'is', null);

  const coveredTechniques = new Set((rules || []).map(r => r.mitre_technique));

  const gaps = await adversarySim.getDetectionGaps(coveredTechniques, tenantId);

  res.json({
    success:   true,
    gaps_count: gaps.length,
    gaps,
    covered_techniques: coveredTechniques.size,
    recommendation: gaps.length > 0
      ? `${gaps.length} ATT&CK techniques have no detection coverage. Priority: ${gaps.filter(g => g.priority === 'HIGH').length} HIGH`
      : 'Full ATT&CK coverage achieved',
  });
}));

/**
 * POST /api/purple-team/caldera/execute
 * Execute a Caldera ability (requires CALDERA_URL env var)
 */
router.post(
  '/caldera/execute',
  requireRole(['ADMIN', 'SUPER_ADMIN']),
  asyncHandler(async (req, res) => {
    const parsed = CalderaExecuteSchema.safeParse(req.body);
    if (!parsed.success) throw createError(400, parsed.error.message);

    const calderaUrl = process.env.CALDERA_URL;
    const calderaKey = process.env.CALDERA_API_KEY;

    if (!calderaUrl || !calderaKey) {
      throw createError(503, 'Caldera integration not configured (CALDERA_URL, CALDERA_API_KEY required)');
    }

    const result = await adversarySim.executeCalderaAbility({
      ...parsed.data,
      caldera_url: calderaUrl,
      api_key:     calderaKey,
      tenant_id:   req.tenantId,
    });

    res.json({ success: true, result });
  })
);

/**
 * GET /api/purple-team/caldera/operations
 * List Caldera operations
 */
router.get('/caldera/operations', requireRole(['ADMIN', 'SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const calderaUrl = process.env.CALDERA_URL;
  const calderaKey = process.env.CALDERA_API_KEY;

  if (!calderaUrl || !calderaKey) {
    return res.json({ success: true, operations: [], message: 'Caldera not configured' });
  }

  const operations = await adversarySim.listCalderaOperations({ caldera_url: calderaUrl, api_key: calderaKey });
  res.json({ success: true, operations });
}));

/**
 * GET /api/purple-team/results/history
 * Historical simulation results
 */
router.get('/results/history', asyncHandler(async (req, res) => {
  const tenantId = req.tenantId;
  const limit    = Math.min(parseInt(req.query.limit || '20', 10), 100);

  const history = await adversarySim.getSessionHistory(tenantId, limit);

  res.json({
    success: true,
    count:   history.length,
    data:    history,
  });
}));

// ── Helper ────────────────────────────────────────────────────────
function coverageGrade(pct) {
  if (pct >= 90) return 'A';
  if (pct >= 75) return 'B';
  if (pct >= 60) return 'C';
  if (pct >= 40) return 'D';
  return 'F';
}

module.exports = router;
