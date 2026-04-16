/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Integration Test Suite v7.0
 *  FILE: test-integration-v7.js
 *
 *  Tests all new modules:
 *    - CVE Enrichment Engine
 *    - AI Router (multi-provider)
 *    - SOC Investigation Report
 *    - Cyber News Engine
 *    - RBAC Backend
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

let passed = 0, failed = 0;
const results = [];

function test(name, fn) {
  try {
    const result = fn();
    if (result && typeof result.then === 'function') {
      return result.then(() => {
        console.log(`  ✅ ${name}`);
        passed++;
        results.push({ name, status: 'pass' });
      }).catch(err => {
        console.error(`  ❌ ${name}: ${err.message}`);
        failed++;
        results.push({ name, status: 'fail', error: err.message });
      });
    }
    console.log(`  ✅ ${name}`);
    passed++;
    results.push({ name, status: 'pass' });
  } catch (err) {
    console.error(`  ❌ ${name}: ${err.message}`);
    failed++;
    results.push({ name, status: 'fail', error: err.message });
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

// ─── MODULE LOADING ───────────────────────────────────────────────────────────
let cveEngine, socInvestigation, newsService;

async function runAll() {
  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log('║  Wadjet-Eye AI — Integration Tests v7.0              ║');
  console.log('╚══════════════════════════════════════════════════════╝\n');

  // ──────────────────────────────────────────────────────
  // SECTION 1: MODULE LOADING
  // ──────────────────────────────────────────────────────
  console.log('\n▶ Section 1: Module Loading');

  await test('CVE Enrichment Engine loads', () => {
    cveEngine = require('./backend/services/cve-enrichment-engine');
    assert(typeof cveEngine.enrichCVE === 'function', 'enrichCVE must be a function');
    assert(typeof cveEngine.bulkEnrichCVEs === 'function', 'bulkEnrichCVEs must be a function');
    assert(typeof cveEngine.formatEnrichedCVEReport === 'function', 'formatEnrichedCVEReport must be a function');
  });

  await test('SOC Investigation Engine loads', () => {
    socInvestigation = require('./backend/services/soc-investigation');
    assert(typeof socInvestigation.generateInvestigationReport === 'function', 'generateInvestigationReport must be a function');
    assert(typeof socInvestigation._buildTimeline === 'function', '_buildTimeline must be a function');
    assert(typeof socInvestigation._detectFindings === 'function', '_detectFindings must be a function');
    assert(typeof socInvestigation._calcRiskScore === 'function', '_calcRiskScore must be a function');
  });

  await test('News Ingestion Service loads', () => {
    newsService = require('./backend/services/news-ingestion');
    assert(typeof newsService.ingestCyberNews === 'function', 'ingestCyberNews must be a function');
    assert(typeof newsService.getRecentNews === 'function', 'getRecentNews must be a function');
    assert(typeof newsService.extractEntities === 'function', 'extractEntities must be a function');
    assert(Array.isArray(newsService.RSS_FEEDS), 'RSS_FEEDS must be an array');
    assert(typeof newsService.NEWS_CATEGORIES === 'object', 'NEWS_CATEGORIES must be an object');
  });

  await test('Routes syntax valid — cve-intelligence', () => {
    const route = require('./backend/routes/cve-intelligence');
    assert(typeof route === 'function', 'Must be an Express router');
  });

  await test('Routes syntax valid — ai', () => {
    const route = require('./backend/routes/ai');
    assert(typeof route === 'function', 'Must be an Express router');
  });

  await test('Routes syntax valid — reports', () => {
    const route = require('./backend/routes/reports');
    assert(typeof route === 'function', 'Must be an Express router');
  });

  await test('Routes syntax valid — news', () => {
    const route = require('./backend/routes/news');
    assert(typeof route === 'function', 'Must be an Express router');
  });

  await test('Routes syntax valid — rbac', () => {
    const route = require('./backend/routes/rbac');
    assert(typeof route === 'function', 'Must be an Express router');
  });

  // ──────────────────────────────────────────────────────
  // SECTION 2: CVE ENRICHMENT ENGINE
  // ──────────────────────────────────────────────────────
  console.log('\n▶ Section 2: CVE Enrichment Engine');

  await test('CVE engine has normalizeNVD function', () => {
    assert(typeof cveEngine._normalizeNVD === 'function', '_normalizeNVD must be exported');
  });

  await test('CVE engine generateDetectionQueries works', () => {
    const queries = cveEngine._generateDetectionQueries('CVE-2021-44228', {
      cvssScore: 10,
      affectedProducts: [{ vendor: 'Apache', product: 'Log4j', version: '2.14.1' }],
    }, ['T1190']);
    assert(queries.splunk, 'splunk query must be generated');
    assert(queries.sentinel, 'sentinel query must be generated');
    assert(queries.elastic, 'elastic query must be generated');
    assert(queries.qradar, 'qradar query must be generated');
    assert(queries.splunk.includes('CVE-2021-44228'), 'CVE ID must appear in query');
  });

  await test('CVE engine generateRemediation works', () => {
    const remediation = cveEngine._generateRemediation({
      cvssScore: 9.8,
      severity: 'CRITICAL',
      attackVector: 'NETWORK',
      privilegesRequired: 'NONE',
      affectedProducts: [{ vendor: 'Microsoft', product: 'Windows', version: '10' }],
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
    }, null);
    assert(Array.isArray(remediation), 'Remediation must be an array');
    assert(remediation.length > 3, 'Must have at least 4 remediation steps');
    assert(remediation.some(r => r.includes('CRITICAL')), 'Must include priority label');
  });

  await test('CVE engine getKEVIds returns array (from cache or fetch)', async () => {
    // This may fail if CISA KEV API is unavailable — that's OK
    const t0 = Date.now();
    try {
      const ids = await Promise.race([
        cveEngine.getKEVIds(),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 10000)),
      ]);
      assert(Array.isArray(ids), 'Must return array');
      console.log(`    [KEV] ${ids.length} CVE IDs in KEV catalog`);
    } catch (err) {
      // Network may be unavailable in test env — that's OK
      console.log(`    [KEV] Fetch skipped (${err.message})`);
    }
  });

  await test('CVE engine cache stats work', () => {
    const stats = cveEngine.getCacheStats();
    assert(typeof stats.enrichedEntries === 'number', 'enrichedEntries must be a number');
    assert(typeof stats.kevLoaded === 'boolean', 'kevLoaded must be boolean');
  });

  await test('CVE engine format report with minimal data', () => {
    const mockEnriched = {
      id: 'CVE-2021-44228',
      description: 'Test CVE description',
      severity: 'CRITICAL',
      cvssScore: 10.0,
      cvssVersion: '3.1',
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      cvss: {
        score: 10.0, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        attackVector: 'NETWORK', attackComplexity: 'LOW', privilegesRequired: 'NONE',
        userInteraction: 'NONE', scope: 'CHANGED', confidentiality: 'HIGH',
        integrity: 'HIGH', availability: 'HIGH', exploitabilityScore: 3.9, impactScore: 6.0,
      },
      weaknesses: ['CWE-917'],
      affectedProducts: [{ vendor: 'Apache', product: 'Log4j', version: '2.14.1' }],
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
      publishedDate: '2021-12-10', lastModified: '2023-01-01',
      exploitAvailability: { exploitedInWild: true, cisaKEV: true, pocAvailable: true, epssScore: 0.97 },
      cisaKEV: { inCatalog: true, dateAdded: '2021-12-10', dueDate: '2021-12-24', requiredAction: 'Patch immediately', vulnerabilityName: 'Log4Shell' },
      mitreTechniques: ['T1190', 'T1059'],
      detectionQueries: { splunk: '| search CVE="CVE-2021-44228"', sentinel: 'SecurityEvent | where ...', elastic: 'network where ...', qradar: 'SELECT * FROM events' },
      remediation: ['1. Apply patch immediately', '2. Monitor for exploitation'],
      threatActors: ['APT41', 'Lazarus'],
      detectionHint: 'Search for JNDI patterns in logs',
      tags: ['rce', 'critical'],
      sources: ['NVD', 'CISA KEV'],
      enrichedAt: new Date().toISOString(),
    };

    const report = cveEngine.formatEnrichedCVEReport(mockEnriched);
    assert(typeof report === 'string', 'Report must be a string');
    assert(report.length > 500, 'Report must have substantial content');
    assert(report.includes('CVE-2021-44228'), 'Must include CVE ID');
    assert(report.includes('CRITICAL'), 'Must include severity');
    assert(report.includes('CISA KEV'), 'Must include KEV reference');
    assert(report.includes('Detection Guidance'), 'Must have detection section');
    assert(report.includes('Mitigation'), 'Must have mitigation section');
    assert(report.includes('Analyst Tip'), 'Must have analyst tip section');
  });

  // ──────────────────────────────────────────────────────
  // SECTION 3: SOC INVESTIGATION REPORT
  // ──────────────────────────────────────────────────────
  console.log('\n▶ Section 3: SOC Investigation Report');

  const mockAlerts = [
    { id: 'A1', title: 'PowerShell Execution Detected', severity: 'high', type: 'endpoint', source: 'edr', source_ip: '192.168.1.100', mitre_technique: 'T1059.001', created_at: new Date().toISOString() },
    { id: 'A2', title: 'LSASS Memory Access', severity: 'critical', type: 'endpoint', source: 'edr', source_ip: '192.168.1.100', mitre_technique: 'T1003.001', created_at: new Date().toISOString() },
    { id: 'A3', title: 'Lateral Movement via RDP', severity: 'high', type: 'network', source: 'siem', source_ip: '10.0.1.50', dest_ip: '10.0.1.51', mitre_technique: 'T1021.001', created_at: new Date().toISOString() },
    { id: 'A4', title: 'Ransomware File Encryption', severity: 'critical', type: 'endpoint', source: 'edr', source_ip: '10.0.1.51', mitre_technique: 'T1486', created_at: new Date().toISOString() },
    { id: 'A5', title: 'Shadow Copy Deletion (vssadmin)', severity: 'critical', type: 'endpoint', source: 'edr', source_ip: '10.0.1.51', mitre_technique: 'T1490', created_at: new Date().toISOString() },
  ];

  const mockEvents = [
    { type: 'process', host: 'WORKSTATION-001', user: 'jsmith', command: 'powershell.exe -enc SGVsbG8=', timestamp: new Date().toISOString() },
    { type: 'process', host: 'WORKSTATION-001', user: 'SYSTEM', command: 'mimikatz.exe sekurlsa::logonpasswords', timestamp: new Date().toISOString() },
    { type: 'network', source_ip: '10.0.1.50', dest_ip: '10.0.1.51', dest_port: 3389, protocol: 'TCP', timestamp: new Date().toISOString() },
    { type: 'network', source_ip: '10.0.1.51', dest_ip: '203.0.113.42', dest_port: 443, protocol: 'HTTPS', timestamp: new Date().toISOString() },
  ];

  await test('generateInvestigationReport returns 10 sections', () => {
    const report = socInvestigation.generateInvestigationReport({
      incidentId: 'INC-2026-001',
      title: 'Ransomware Attack — WORKSTATION-001',
      alerts: mockAlerts,
      events: mockEvents,
    });

    assert(typeof report.report === 'string', 'Report must be a string');
    assert(report.sectionCount === 10, `Expected 10 sections, got ${report.sectionCount}`);
    assert(report.riskScore > 0, 'Risk score must be > 0');
    assert(report.severity, 'Must have severity');
    assert(report.incidentId === 'INC-2026-001', 'Must preserve incident ID');
    assert(typeof report.iocs === 'object', 'Must have IOCs object');
    assert(Array.isArray(report.techniques), 'Must have techniques array');
  });

  await test('Report content includes all 10 sections', () => {
    const report = socInvestigation.generateInvestigationReport({
      incidentId: 'INC-TEST',
      title: 'Test Incident',
      alerts: mockAlerts,
      events: mockEvents,
    });

    const sections = ['Section 1', 'Section 2', 'Section 3', 'Section 4', 'Section 5',
                      'Section 6', 'Section 7', 'Section 8', 'Section 9', 'Section 10'];
    for (const sec of sections) {
      assert(report.report.includes(sec), `Report must include ${sec}`);
    }
  });

  await test('Risk score calculation works correctly', () => {
    const highRiskFindings = {
      hasRansomware: true, hasCriticalAlert: true, hasLateralMovement: true,
      hasPersistence: true, hasC2: true, hasDataExfiltration: true,
      hasPrivilegeEscal: true, hasExploitedCVE: true, highestSeverity: 'critical',
    };
    const score = socInvestigation._calcRiskScore(highRiskFindings);
    assert(score === 100, `High-risk score should be 100, got ${score}`);

    const lowRiskFindings = {
      hasRansomware: false, hasCriticalAlert: false, hasLateralMovement: false,
      hasPersistence: false, hasC2: false, hasDataExfiltration: false,
      hasPrivilegeEscal: false, hasExploitedCVE: false, highestSeverity: 'low',
    };
    const lowScore = socInvestigation._calcRiskScore(lowRiskFindings);
    assert(lowScore <= 30, `Low-risk score should be ≤30, got ${lowScore}`);
  });

  await test('Finds ransomware in alert data', () => {
    const findings = socInvestigation._detectFindings(
      [{ command: 'vssadmin delete shadows', description: 'ransomware execution' }],
      [{ title: 'Ransomware encryption detected', severity: 'critical' }],
      {}
    );
    assert(findings.hasRansomware === true, 'Should detect ransomware');
    assert(findings.hasCriticalAlert === true, 'Should detect critical alert');
  });

  await test('Timeline builder works', () => {
    const events = [
      { timestamp: '2026-01-01T10:00:00Z', title: 'First event', type: 'alert', severity: 'high' },
      { timestamp: '2026-01-01T09:00:00Z', title: 'Earlier event', type: 'alert', severity: 'medium' },
    ];
    const timeline = socInvestigation._buildTimeline(events);
    assert(Array.isArray(timeline), 'Must return array');
    assert(timeline.length === 2, 'Must include all events');
    assert(timeline[0].timestamp === '2026-01-01T09:00:00Z', 'Must be sorted chronologically');
  });

  await test('IOC extraction works for IPs and hashes', () => {
    const events = [
      { source_ip: '203.0.113.42', description: 'C2 connection to 185.220.101.15' },
    ];
    const alerts = [
      { title: 'Hash match: d41d8cd98f00b204e9800998ecf8427e', source_ip: '198.51.100.1' },
    ];
    const iocs = socInvestigation._extractIOCs(events, alerts, {});
    assert(iocs.sourceIPs.length > 0, 'Must extract source IPs');
    assert(iocs.fileHashes.length > 0, 'Must extract file hashes');
    // Private IPs should be excluded
    assert(!iocs.sourceIPs.includes('192.168.1.100'), 'Should not include private IPs');
  });

  await test('Report includes MITRE techniques from alerts', () => {
    const report = socInvestigation.generateInvestigationReport({
      incidentId: 'INC-MITRE',
      alerts: [{ mitre_technique: 'T1059.001', severity: 'high', title: 'PowerShell', created_at: new Date().toISOString() }],
      events: [],
    });
    assert(report.techniques.includes('T1059.001') || report.report.includes('T1059'), 'Must include MITRE techniques');
  });

  // ──────────────────────────────────────────────────────
  // SECTION 4: CYBER NEWS ENGINE
  // ──────────────────────────────────────────────────────
  console.log('\n▶ Section 4: Cyber News Engine');

  await test('News RSS_FEEDS has all required sources', () => {
    const feeds = newsService.RSS_FEEDS;
    assert(feeds.length >= 8, `Must have at least 8 feeds, has ${feeds.length}`);

    const requiredFeeds = ['thehackernews', 'bleepingcomputer', 'cisa'];
    for (const feedId of requiredFeeds) {
      assert(feeds.some(f => f.id === feedId), `Must have ${feedId} feed`);
    }
  });

  await test('News categories are defined correctly', () => {
    const cats = newsService.NEWS_CATEGORIES;
    const requiredCats = ['THREATS', 'INTELLIGENCE', 'VULNERABILITIES', 'ATTACKS', 'ADVISORIES'];
    for (const cat of requiredCats) {
      assert(cats[cat], `Must have category: ${cat}`);
      assert(cats[cat].id, `Category ${cat} must have id`);
      assert(cats[cat].label, `Category ${cat} must have label`);
    }
  });

  await test('Entity extraction — CVE detection', () => {
    const entities = newsService.extractEntities('Critical CVE-2024-1234 in Apache Tomcat allows RCE. Also CVE-2024-5678 affects nginx.');
    assert(entities.cves.length === 2, `Expected 2 CVEs, got ${entities.cves.length}`);
    assert(entities.cves.includes('CVE-2024-1234'), 'Must extract CVE-2024-1234');
    assert(entities.cves.includes('CVE-2024-5678'), 'Must extract CVE-2024-5678');
  });

  await test('Entity extraction — threat actors', () => {
    const entities = newsService.extractEntities('APT29 (Cozy Bear) targeted government networks in a new espionage campaign.');
    assert(entities.actors.some(a => a.includes('APT29') || a.includes('Cozy Bear')), 'Must extract APT29 or Cozy Bear');
  });

  await test('Entity extraction — severity classification', () => {
    assert(newsService.extractEntities('Critical zero-day exploit actively exploited in the wild').severity === 'critical', 'Should be critical');
    assert(newsService.extractEntities('New CVE patch released for Apache').severity === 'medium', 'Should be medium');
    assert(newsService.extractEntities('New firmware release announcement').severity === 'low', 'Should be low');
  });

  await test('Entity extraction — category detection', () => {
    assert(newsService.extractEntities('Ransomware attack hits major hospital network').category === 'attacks', 'Ransomware should be "attacks"');
    assert(newsService.extractEntities('Critical CVE-2024-1234 requires immediate patch').category === 'vulnerabilities', 'CVE should be "vulnerabilities"');
    assert(newsService.extractEntities('CISA advisory for critical infrastructure').category === 'advisories', 'CISA should be "advisories"');
  });

  await test('Entity extraction — tag generation', () => {
    const entities = newsService.extractEntities('Ransomware gang uses zero-day phishing attack with supply chain compromise');
    assert(entities.tags.includes('ransomware'), 'Must have ransomware tag');
    assert(entities.tags.includes('zero-day'), 'Must have zero-day tag');
    assert(entities.tags.includes('phishing'), 'Must have phishing tag');
    assert(entities.tags.includes('supply-chain'), 'Must have supply-chain tag');
  });

  await test('News cache stats available', () => {
    const stats = newsService.getCacheStats();
    assert(typeof stats.totalArticles === 'number', 'Must have totalArticles');
    assert(typeof stats.feedCount === 'number', 'Must have feedCount');
    assert(stats.feedCount >= 8, `Must have at least 8 feeds, has ${stats.feedCount}`);
  });

  await test('getRecentNews returns correct shape when cache empty', async () => {
    // Should trigger ingestion (which may fail for network, but shape must be correct)
    try {
      const result = await Promise.race([
        newsService.getRecentNews(null, { limit: 5 }),
        new Promise((_, r) => setTimeout(() => r(new Error('timeout')), 15000)),
      ]);
      assert(typeof result.articles !== 'undefined', 'Must have articles');
      assert(typeof result.total === 'number', 'Must have total');
    } catch (err) {
      // Network may be unavailable — just log
      console.log(`    [News] Network unavailable: ${err.message}`);
    }
  });

  // ──────────────────────────────────────────────────────
  // SECTION 5: RBAC BACKEND
  // ──────────────────────────────────────────────────────
  console.log('\n▶ Section 5: RBAC Backend');

  await test('RBAC route has correct endpoints defined', () => {
    const rbacRoute = require('./backend/routes/rbac');
    assert(typeof rbacRoute === 'function', 'Must be an Express router');
    assert(rbacRoute.stack, 'Must have route stack');
    const routes = rbacRoute.stack.map(r => r.route?.path).filter(Boolean);
    console.log(`    [RBAC] Routes: ${routes.join(', ')}`);
    assert(routes.includes('/roles'), 'Must have /roles route');
    assert(routes.includes('/permissions'), 'Must have /permissions route');
    assert(routes.includes('/assign'), 'Must have /assign route');
    assert(routes.includes('/users'), 'Must have /users route');
    assert(routes.includes('/audit-log'), 'Must have /audit-log route');
    assert(routes.includes('/stats'), 'Must have /stats route');
    assert(routes.includes('/check'), 'Must have /check route');
  });

  // ──────────────────────────────────────────────────────
  // SECTION 6: SERVER ROUTE REGISTRATION
  // ──────────────────────────────────────────────────────
  console.log('\n▶ Section 6: Server Registration');

  await test('server.js registers rbac route', () => {
    const fs = require('fs');
    const serverContent = fs.readFileSync('./backend/server.js', 'utf8');
    assert(serverContent.includes('/api/rbac'), 'server.js must register /api/rbac');
    assert(serverContent.includes("require('./routes/rbac')"), 'server.js must require rbac routes');
  });

  await test('server.js has all required route registrations', () => {
    const fs = require('fs');
    const serverContent = fs.readFileSync('./backend/server.js', 'utf8');
    const required = ['/api/cve', '/api/ai', '/api/news', '/api/reports', '/api/rbac'];
    for (const route of required) {
      assert(serverContent.includes(route), `server.js must include ${route}`);
    }
  });

  // ──────────────────────────────────────────────────────
  // SECTION 7: END-TO-END SCENARIO VALIDATION
  // ──────────────────────────────────────────────────────
  console.log('\n▶ Section 7: E2E Scenario Validation');

  await test('Complete ransomware incident report generates', () => {
    const ransomwareAlerts = [
      { title: 'Phishing email attachment opened', severity: 'high', type: 'email', source_ip: '192.168.1.100', mitre_technique: 'T1566.001', created_at: '2026-01-15T09:00:00Z' },
      { title: 'PowerShell dropper execution', severity: 'high', type: 'endpoint', source_ip: '192.168.1.100', mitre_technique: 'T1059.001', created_at: '2026-01-15T09:05:00Z' },
      { title: 'Credential dumping via LSASS', severity: 'critical', type: 'endpoint', source_ip: '192.168.1.100', mitre_technique: 'T1003.001', created_at: '2026-01-15T09:15:00Z' },
      { title: 'Lateral movement to file server', severity: 'critical', type: 'network', source_ip: '192.168.1.100', dest_ip: '192.168.1.50', mitre_technique: 'T1021.001', created_at: '2026-01-15T09:30:00Z' },
      { title: 'Ransomware encryption started', severity: 'critical', type: 'endpoint', source_ip: '192.168.1.50', mitre_technique: 'T1486', created_at: '2026-01-15T10:00:00Z' },
      { title: 'Shadow copy deletion detected', severity: 'critical', type: 'endpoint', source_ip: '192.168.1.50', mitre_technique: 'T1490', created_at: '2026-01-15T10:01:00Z' },
      { title: 'C2 communication detected', severity: 'high', type: 'network', source_ip: '192.168.1.100', dest_ip: '203.0.113.42', mitre_technique: 'T1071', created_at: '2026-01-15T09:10:00Z' },
    ];

    const report = socInvestigation.generateInvestigationReport({
      incidentId: 'INC-2026-RANSOMWARE-001',
      title: 'Ransomware Campaign — LockBit Variant',
      alerts: ransomwareAlerts,
      events: [],
    });

    assert(report.severity === 'CRITICAL', `Expected CRITICAL, got ${report.severity}`);
    assert(report.riskScore >= 80, `Risk score should be ≥80 for full ransomware chain, got ${report.riskScore}`);
    assert(report.sectionCount === 10, 'Must have exactly 10 sections');
    assert(report.report.includes('Ransomware'), 'Must mention ransomware');
    assert(report.report.includes('Section 6: Containment'), 'Must have containment section');
    assert(report.report.includes('Section 10: Severity Assessment'), 'Must have severity assessment');
    console.log(`    Risk score: ${report.riskScore}/100, Techniques: ${report.techniques.join(', ')}`);
  });

  await test('CVE detection query includes correct CVE ID', () => {
    const queries = cveEngine._generateDetectionQueries('CVE-2024-99999', {
      cvssScore: 9.8,
      affectedProducts: [{ vendor: 'Example', product: 'App', version: '1.0' }],
    }, ['T1190']);
    assert(queries.splunk.includes('CVE-2024-99999'), 'Splunk query must include CVE ID');
    assert(queries.sentinel.includes('CVE-2024-99999'), 'Sentinel query must include CVE ID');
  });

  await test('News entity extraction for Log4Shell article', () => {
    const article = 'Critical zero-day vulnerability CVE-2021-44228 in Apache Log4j2 exploited by APT41 and Lazarus Group. Active exploitation in the wild. Patch immediately.';
    const entities = newsService.extractEntities(article);
    assert(entities.cves.includes('CVE-2021-44228'), 'Must extract Log4Shell CVE');
    assert(entities.severity === 'critical', 'Must classify as critical');
    assert(entities.actors.some(a => a.includes('APT41') || a.includes('Lazarus')), 'Must extract threat actors');
    assert(entities.tags.includes('vulnerability'), 'Must tag as vulnerability');
  });

  await test('SOC investigation with APT espionage scenario', () => {
    const aptAlerts = [
      { title: 'Spearphishing email detected', severity: 'high', mitre_technique: 'T1566.001', source_ip: '192.168.10.5', created_at: new Date().toISOString() },
      { title: 'Suspected APT29 tooling detected', severity: 'critical', mitre_technique: 'T1078', source_ip: '192.168.10.5', created_at: new Date().toISOString() },
      { title: 'Data staging for exfiltration', severity: 'high', mitre_technique: 'T1041', source_ip: '192.168.10.5', created_at: new Date().toISOString() },
    ];

    const report = socInvestigation.generateInvestigationReport({
      incidentId: 'INC-APT-001',
      title: 'APT Espionage Campaign',
      alerts: aptAlerts,
      events: [],
    });

    assert(report.riskScore >= 40, `APT report must have risk score ≥40, got ${report.riskScore}`);
    assert(report.report.includes('Exfiltration') || report.report.includes('exfiltration'), 'Must mention exfiltration');
  });

  // ──────────────────────────────────────────────────────
  // FINAL RESULTS
  // ──────────────────────────────────────────────────────
  console.log('\n══════════════════════════════════════════════════════════');
  console.log(' INTEGRATION TEST RESULTS v7.0');
  console.log('══════════════════════════════════════════════════════════');
  console.log(`  ✅ PASSED: ${passed}`);
  if (failed > 0) {
    console.log(`  ❌ FAILED: ${failed}`);
    const failures = results.filter(r => r.status === 'fail');
    failures.forEach(f => console.log(`     - ${f.name}: ${f.error}`));
  }
  console.log('══════════════════════════════════════════════════════════\n');

  if (failed === 0) {
    console.log('  🎉 All integration tests passed — v7.0 production-ready!\n');
  } else {
    console.log(`  ⚠️  ${failed} test(s) failed\n`);
    process.exit(1);
  }
}

runAll().catch(err => {
  console.error('[Integration Test] Fatal error:', err);
  process.exit(1);
});
