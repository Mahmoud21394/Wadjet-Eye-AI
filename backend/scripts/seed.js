#!/usr/bin/env node
/**
 * ══════════════════════════════════════════════════════════════════
 *  EYEbot AI — Production Database Seeder
 *  Version: 2.0.0
 *
 *  Creates:
 *    ✓ 3 demo tenant organisations
 *    ✓ 3 users (SUPER_ADMIN, ANALYST, VIEWER) with hashed passwords
 *    ✓ 5 sample alerts
 *    ✓ 3 sample cases
 *    ✓ 5 sample IOCs
 *    ✓ 3 playbooks
 *
 *  Usage:
 *    cd backend
 *    node scripts/seed.js
 *
 *  Requirements:
 *    • .env must exist with valid SUPABASE_URL + SUPABASE_SERVICE_KEY
 *    • Supabase schema must already be applied (run database/schema.sql first)
 * ══════════════════════════════════════════════════════════════════
 */

'use strict';

// Load environment variables FIRST before any other imports
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// ── Validate env before connecting ──────────────────────────────
const REQUIRED_ENV = ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY'];
const missing = REQUIRED_ENV.filter(k => !process.env[k]);
if (missing.length) {
  console.error(`\n❌ Missing required environment variables:\n   ${missing.join(', ')}`);
  console.error('   Copy backend/.env.example → backend/.env and fill in your values.\n');
  process.exit(1);
}

const { createClient } = require('@supabase/supabase-js');

// ── Supabase admin client (service role — bypasses RLS) ──────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  {
    auth: { autoRefreshToken: false, persistSession: false },
    db:   { schema: 'public' }
  }
);

// ════════════════════════════════════════════════════════════════
//  SEED DATA DEFINITIONS
// ════════════════════════════════════════════════════════════════

// ── Tenant IDs (fixed UUIDs for reproducibility) ────────────────
const TENANT_IDS = {
  mssp:       '00000000-0000-0000-0000-000000000001',
  hackerone:  '00000000-0000-0000-0000-000000000002',
  bugcrowd:   '00000000-0000-0000-0000-000000000003',
};

// ── Seed Users ───────────────────────────────────────────────────
// Passwords are passed to Supabase Auth which handles hashing
// (Supabase uses bcrypt internally via GoTrue)
const SEED_USERS = [
  {
    email:     'mahmoud@mssp.com',
    password:  'EYEbot@2024!',        // SUPER_ADMIN — change after first login
    name:      'Mahmoud Osman',
    role:      'SUPER_ADMIN',
    tenant_id: TENANT_IDS.mssp,
    avatar:    'MO',
    permissions: ['all'],
    label:     'Super Admin (Full Access)',
  },
  {
    email:     'analyst@mssp.com',
    password:  'Analyst@Secure2024!',       // ANALYST
    name:      'James Chen',
    role:      'ANALYST',
    tenant_id: TENANT_IDS.mssp,
    avatar:    'JC',
    permissions: ['read', 'investigate', 'create_alerts', 'manage_iocs'],
    label:     'Analyst (Read + Investigate)',
  },
  {
    email:     'viewer@hackerone.com',
    password:  'Viewer@ReadOnly2024!',      // VIEWER
    name:      'Priya Patel',
    role:      'VIEWER',
    tenant_id: TENANT_IDS.hackerone,
    avatar:    'PP',
    permissions: ['read'],
    label:     'Viewer (Read Only)',
  },
];

// ── Seed Tenants ─────────────────────────────────────────────────
const SEED_TENANTS = [
  {
    id:            TENANT_IDS.mssp,
    name:          'MSSP Global Operations',
    short_name:    'mssp-global',
    domain:        'mssp.threatpilot.ai',
    plan:          'enterprise',
    risk_level:    'high',
    contact_email: 'admin@mssp.threatpilot.ai',
    active:        true,
    settings: {
      alerts_enabled:        true,
      auto_playbooks:        true,
      dark_web_monitoring:   true,
      cross_tenant_learning: false,
    },
  },
  {
    id:            TENANT_IDS.hackerone,
    name:          'HackerOne Security',
    short_name:    'hackerone',
    domain:        'h1.threatpilot.ai',
    plan:          'professional',
    risk_level:    'medium',
    contact_email: 'admin@h1.threatpilot.ai',
    active:        true,
    settings: {
      alerts_enabled:        true,
      auto_playbooks:        false,
      dark_web_monitoring:   true,
      cross_tenant_learning: false,
    },
  },
  {
    id:            TENANT_IDS.bugcrowd,
    name:          'Bugcrowd Platform',
    short_name:    'bugcrowd',
    domain:        'bc.threatpilot.ai',
    plan:          'starter',
    risk_level:    'low',
    contact_email: 'admin@bc.threatpilot.ai',
    active:        true,
    settings: {
      alerts_enabled:      true,
      auto_playbooks:      false,
      dark_web_monitoring: false,
    },
  },
];

// ── Sample Alerts ─────────────────────────────────────────────────
const SEED_ALERTS = (adminUserId) => [
  {
    tenant_id:       TENANT_IDS.mssp,
    title:           'APT29 C2 Communication Detected',
    description:     'Outbound traffic to known APT29 command-and-control IP 185.220.101.45 detected from workstation DESKTOP-A4F2K1',
    severity:        'CRITICAL',
    status:          'open',
    type:            'apt',
    ioc_value:       '185.220.101.45',
    ioc_type:        'ip',
    source:          'EDR',
    mitre_technique: 'T1071.001',
    affected_assets: ['DESKTOP-A4F2K1', '10.0.0.45'],
    metadata:        { confidence: 94, campaign: 'Operation Midnight Rain' },
    created_by:      adminUserId,
  },
  {
    tenant_id:       TENANT_IDS.mssp,
    title:           'Critical CVE-2024-3400 Exploit Attempt',
    description:     'PAN-OS GlobalProtect zero-day exploitation attempt detected. Unauthenticated RCE attempt against perimeter firewall.',
    severity:        'CRITICAL',
    status:          'in_progress',
    type:            'vulnerability',
    ioc_value:       'CVE-2024-3400',
    ioc_type:        'cve',
    source:          'SIEM',
    mitre_technique: 'T1190',
    affected_assets: ['FW-EDGE-01'],
    metadata:        { cvss: 10.0, patch_available: true },
    created_by:      adminUserId,
  },
  {
    tenant_id:       TENANT_IDS.mssp,
    title:           'Credential Dump — LSASS Memory Access',
    description:     'Suspicious access to lsass.exe memory detected. Possible credential harvesting via Mimikatz or similar tool.',
    severity:        'HIGH',
    status:          'open',
    type:            'malware',
    ioc_value:       'lsass.exe',
    ioc_type:        'filename',
    source:          'EDR',
    mitre_technique: 'T1003.001',
    affected_assets: ['SRV-DC-02'],
    metadata:        { process_id: 1234, parent_process: 'cmd.exe' },
    created_by:      adminUserId,
  },
  {
    tenant_id:       TENANT_IDS.hackerone,
    title:           'Phishing Domain Detected — DocuSign Lure',
    description:     'Employee clicked link to phishing domain impersonating DocuSign. Credential harvesting page served via HTTPS.',
    severity:        'HIGH',
    status:          'open',
    type:            'phishing',
    ioc_value:       'docusign-secure-verify[.]net',
    ioc_type:        'domain',
    source:          'Email Gateway',
    mitre_technique: 'T1566.002',
    affected_assets: ['user@hackerone.com'],
    metadata:        { clicked_by: 5, blocked: true },
    created_by:      adminUserId,
  },
  {
    tenant_id:       TENANT_IDS.mssp,
    title:           'Ransomware IOC — LockBit 4.0 Hash',
    description:     'LockBit 4.0 ransomware binary SHA256 hash found on endpoint. File quarantined by AV. Lateral movement attempted.',
    severity:        'CRITICAL',
    status:          'escalated',
    type:            'ransomware',
    ioc_value:       'a3f2b1c9d4e5f678901234567890abcdef1234567890abcdef1234567890abc',
    ioc_type:        'hash_sha256',
    source:          'AV',
    mitre_technique: 'T1486',
    affected_assets: ['LAPTOP-HR-012'],
    metadata:        { family: 'LockBit 4.0', quarantined: true },
    created_by:      adminUserId,
  },
];

// ── Sample IOCs ───────────────────────────────────────────────────
const SEED_IOCS = (adminUserId) => [
  {
    tenant_id:   TENANT_IDS.mssp,
    value:       '185.220.101.45',
    type:        'ip',
    reputation:  'malicious',
    risk_score:  94,
    source:      'VirusTotal',
    country:     'DE',
    asn:         'AS51167 Contabo GmbH',
    threat_actor:'APT29',
    tags:        ['C2', 'Tor Exit'],
    status:      'active',
    first_seen:  '2024-11-01T00:00:00Z',
    last_seen:   new Date().toISOString(),
    created_by:  adminUserId,
  },
  {
    tenant_id:   TENANT_IDS.mssp,
    value:       'maliciousupdate[.]ru',
    type:        'domain',
    reputation:  'malicious',
    risk_score:  89,
    source:      'AlienVault OTX',
    country:     'RU',
    asn:         'AS48666',
    threat_actor:'APT29',
    tags:        ['Phishing', 'C2', 'Malware Distribution'],
    status:      'active',
    first_seen:  '2024-12-01T00:00:00Z',
    last_seen:   new Date().toISOString(),
    created_by:  adminUserId,
  },
  {
    tenant_id:   TENANT_IDS.mssp,
    value:       'a3f2b1c9d4e5f678901234567890abcdef1234567890abcdef1234567890abc',
    type:        'hash_sha256',
    reputation:  'malicious',
    risk_score:  97,
    source:      'Mandiant',
    country:     null,
    asn:         null,
    threat_actor:'LockBit',
    tags:        ['Ransomware', 'LockBit 4.0'],
    status:      'active',
    first_seen:  '2025-01-10T00:00:00Z',
    last_seen:   new Date().toISOString(),
    created_by:  adminUserId,
  },
  {
    tenant_id:   TENANT_IDS.hackerone,
    value:       'docusign-secure-verify[.]net',
    type:        'domain',
    reputation:  'malicious',
    risk_score:  88,
    source:      'URLhaus',
    country:     'UA',
    asn:         'AS9123',
    threat_actor:'TA558',
    tags:        ['Phishing', 'DocuSign Lure'],
    status:      'active',
    first_seen:  '2025-02-01T00:00:00Z',
    last_seen:   new Date().toISOString(),
    created_by:  adminUserId,
  },
  {
    tenant_id:   TENANT_IDS.mssp,
    value:       '5.34.178.24',
    type:        'ip',
    reputation:  'malicious',
    risk_score:  85,
    source:      'Shodan',
    country:     'RU',
    asn:         'AS44050',
    threat_actor:'Sandworm',
    tags:        ['C2', 'Botnet'],
    status:      'active',
    first_seen:  '2024-09-01T00:00:00Z',
    last_seen:   new Date().toISOString(),
    created_by:  adminUserId,
  },
];

// ── Sample Cases ──────────────────────────────────────────────────
const SEED_CASES = (adminUserId) => [
  {
    tenant_id:    TENANT_IDS.mssp,
    title:        'APT29 Intrusion — Operation Midnight Rain Response',
    description:  'Active APT29 campaign detected across 3 endpoints. C2 traffic confirmed. Immediate containment required.',
    severity:     'CRITICAL',
    status:       'in_progress',
    assigned_to:  adminUserId,
    created_by:   adminUserId,
    tags:         ['APT29', 'C2', 'Lateral Movement', 'Urgent'],
    sla_deadline: new Date(Date.now() + 4 * 3600000).toISOString(), // 4 hours SLA
    evidence:     [],
  },
  {
    tenant_id:    TENANT_IDS.mssp,
    title:        'LockBit Ransomware — Endpoint Containment',
    description:  'LockBit 4.0 binary detected on LAPTOP-HR-012. HR department endpoint isolated. Investigating for lateral spread.',
    severity:     'CRITICAL',
    status:       'open',
    assigned_to:  adminUserId,
    created_by:   adminUserId,
    tags:         ['Ransomware', 'LockBit', 'Containment'],
    sla_deadline: new Date(Date.now() + 2 * 3600000).toISOString(),
    evidence:     [],
  },
  {
    tenant_id:    TENANT_IDS.hackerone,
    title:        'Phishing Campaign — DocuSign Impersonation',
    description:  'Targeted phishing campaign against HackerOne employees. 5 users clicked malicious link. Credential reset required.',
    severity:     'HIGH',
    status:       'open',
    assigned_to:  adminUserId,
    created_by:   adminUserId,
    tags:         ['Phishing', 'Credential Theft'],
    sla_deadline: new Date(Date.now() + 24 * 3600000).toISOString(),
    evidence:     [],
  },
];

// ── Sample Playbooks ──────────────────────────────────────────────
const SEED_PLAYBOOKS = (adminUserId) => [
  {
    tenant_id:        TENANT_IDS.mssp,
    title:            'Ransomware Initial Response',
    description:      'Immediate containment and investigation steps for ransomware incidents',
    category:         'Ransomware',
    trigger:          'Ransomware IOC detected or file encryption activity observed',
    mitre_techniques: ['T1486', 'T1490', 'T1489'],
    active:           true,
    created_by:       adminUserId,
    steps: [
      { order: 1, title: 'Isolate Affected Endpoint',      tool: 'edr_isolate',    duration_s: 30,  desc: 'Immediately isolate endpoint via EDR to prevent lateral spread' },
      { order: 2, title: 'Preserve Memory Dump',           tool: 'forensics',      duration_s: 120, desc: 'Capture volatile memory before any changes are made' },
      { order: 3, title: 'Identify Ransomware Family',     tool: 'virustotal',     duration_s: 60,  desc: 'Submit hash to VirusTotal for family identification' },
      { order: 4, title: 'Map to MITRE ATT&CK',            tool: 'mitre_map',      duration_s: 20,  desc: 'Map observed TTPs to ATT&CK framework' },
      { order: 5, title: 'Check for Backup Integrity',     tool: 'backup_check',   duration_s: 300, desc: 'Verify backup systems not affected before recovery' },
      { order: 6, title: 'Notify Stakeholders',            tool: 'notify',         duration_s: 10,  desc: 'Alert CISO, legal, and affected business unit' },
    ],
  },
  {
    tenant_id:        TENANT_IDS.mssp,
    title:            'Phishing Response Workflow',
    description:      'Response steps for confirmed phishing attacks targeting employees',
    category:         'Phishing',
    trigger:          'Employee reports phishing email or credential harvesting domain detected',
    mitre_techniques: ['T1566.001', 'T1566.002', 'T1078'],
    active:           true,
    created_by:       adminUserId,
    steps: [
      { order: 1, title: 'Extract and Analyse IOCs',       tool: 'email_parser',   duration_s: 30,  desc: 'Parse email headers, extract URLs, domains, and attachments' },
      { order: 2, title: 'Enrich Phishing Domain',         tool: 'virustotal',     duration_s: 15,  desc: 'Check domain age, reputation, hosting provider' },
      { order: 3, title: 'Block Malicious Domain',         tool: 'dns_block',      duration_s: 5,   desc: 'Push domain to DNS blocklist across all tenants' },
      { order: 4, title: 'Identify Exposed Users',         tool: 'email_search',   duration_s: 60,  desc: 'Search email gateway logs for all recipients' },
      { order: 5, title: 'Force Password Reset',           tool: 'ad_reset',       duration_s: 30,  desc: 'Trigger mandatory password reset for affected users' },
      { order: 6, title: 'Submit Takedown Request',        tool: 'abuse_report',   duration_s: 10,  desc: 'Report phishing domain to registrar and hosting provider' },
    ],
  },
  {
    tenant_id:        TENANT_IDS.mssp,
    title:            'Malicious IP Investigation',
    description:      'Enrichment and response workflow for suspicious or malicious IP addresses',
    category:         'Network Scanning',
    trigger:          'IP with risk score > 80 detected in network traffic or alerts',
    mitre_techniques: ['T1071.001', 'T1095', 'T1571'],
    active:           true,
    created_by:       adminUserId,
    steps: [
      { order: 1, title: 'WHOIS Lookup',                   tool: 'whois_lookup',   duration_s: 5,   desc: 'Identify IP registration, owner, and abuse contacts' },
      { order: 2, title: 'VirusTotal Check',               tool: 'virustotal',     duration_s: 10,  desc: 'Check detection ratio across 70+ AV engines' },
      { order: 3, title: 'AbuseIPDB Reputation',           tool: 'abuseipdb',      duration_s: 8,   desc: 'Check community abuse reports and confidence score' },
      { order: 4, title: 'Shodan Port Scan',               tool: 'shodan_query',   duration_s: 15,  desc: 'Identify open ports, services, and known CVEs' },
      { order: 5, title: 'OTX Threat Intelligence',        tool: 'otx_pulse',      duration_s: 10,  desc: 'Check AlienVault OTX pulse data and threat actor association' },
      { order: 6, title: 'Firewall Block Rule',            tool: 'firewall_block', duration_s: 5,   desc: 'Push automatic block rule to perimeter firewall' },
    ],
  },
];

// ════════════════════════════════════════════════════════════════
//  HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════

function log(msg, type = 'info') {
  const icons = { info: 'ℹ️ ', success: '✅', error: '❌', warn: '⚠️ ', step: '▶️ ' };
  console.log(`${icons[type] || '  '} ${msg}`);
}

function section(title) {
  console.log(`\n${'═'.repeat(55)}`);
  console.log(`  ${title}`);
  console.log(`${'═'.repeat(55)}`);
}

// ════════════════════════════════════════════════════════════════
//  SEED FUNCTIONS
// ════════════════════════════════════════════════════════════════

async function seedTenants() {
  section('SEEDING TENANTS');

  for (const tenant of SEED_TENANTS) {
    // Upsert — safe to re-run
    const { error } = await supabase
      .from('tenants')
      .upsert(tenant, { onConflict: 'id' });

    if (error) {
      log(`Tenant "${tenant.name}": ${error.message}`, 'error');
    } else {
      log(`Tenant "${tenant.name}" (${tenant.plan}) — seeded`, 'success');
    }
  }
}

async function seedUsers() {
  section('SEEDING USERS');

  const createdUsers = [];

  for (const user of SEED_USERS) {
    log(`Creating: ${user.email} [${user.role}] — ${user.label}`, 'step');

    // ── Step 1: Create auth user in Supabase Auth ────────────────
    // Check if auth user already exists
    const { data: existingList } = await supabase.auth.admin.listUsers();
    const existing = existingList?.users?.find(u => u.email === user.email);

    let authUserId;

    if (existing) {
      log(`  Auth user already exists (${existing.id}) — updating password`, 'warn');
      // Update password to ensure it matches our seed value
      const { error: pwErr } = await supabase.auth.admin.updateUserById(existing.id, {
        password: user.password,
        email_confirm: true,
      });
      if (pwErr) log(`  Password update failed: ${pwErr.message}`, 'warn');
      authUserId = existing.id;
    } else {
      const { data: authData, error: authErr } = await supabase.auth.admin.createUser({
        email:           user.email,
        password:        user.password,
        email_confirm:   true,  // Skip email verification for seed users
        user_metadata: {
          name:      user.name,
          role:      user.role,
          tenant_id: user.tenant_id,
        },
      });

      if (authErr) {
        log(`  Auth creation failed: ${authErr.message}`, 'error');
        continue;
      }

      authUserId = authData.user.id;
      log(`  Auth user created: ${authUserId}`, 'success');
    }

    // ── Step 2: Upsert profile in our users table ────────────────
    const { data: profile, error: profileErr } = await supabase
      .from('users')
      .upsert({
        auth_id:     authUserId,
        tenant_id:   user.tenant_id,
        name:        user.name,
        email:       user.email,
        role:        user.role,
        avatar:      user.avatar,
        permissions: user.permissions,
        status:      'active',
        mfa_enabled: false,
      }, { onConflict: 'auth_id' })
      .select()
      .single();

    if (profileErr) {
      log(`  Profile upsert failed: ${profileErr.message}`, 'error');
    } else {
      log(`  Profile upserted: ${profile.id}`, 'success');
      createdUsers.push(profile);
    }
  }

  return createdUsers;
}

async function seedAlerts(adminUserId) {
  section('SEEDING SAMPLE ALERTS');

  // Clear existing seed alerts to avoid duplicates
  await supabase
    .from('alerts')
    .delete()
    .in('tenant_id', Object.values(TENANT_IDS))
    .eq('source', 'EDR');  // Only delete our seeded ones

  const alerts = SEED_ALERTS(adminUserId);

  for (const alert of alerts) {
    const { error } = await supabase.from('alerts').insert(alert);
    if (error) {
      log(`Alert "${alert.title.slice(0, 40)}...": ${error.message}`, 'error');
    } else {
      log(`Alert [${alert.severity}] "${alert.title.slice(0, 50)}"`, 'success');
    }
  }
}

async function seedIOCs(adminUserId) {
  section('SEEDING SAMPLE IOCs');

  const iocs = SEED_IOCS(adminUserId);

  for (const ioc of iocs) {
    // Upsert on tenant+value uniqueness
    const { error } = await supabase
      .from('iocs')
      .upsert(ioc, { onConflict: 'tenant_id,value' });

    if (error) {
      log(`IOC "${ioc.value}": ${error.message}`, 'error');
    } else {
      log(`IOC [${ioc.type}] ${ioc.value} — Risk: ${ioc.risk_score}`, 'success');
    }
  }
}

async function seedCases(adminUserId) {
  section('SEEDING SAMPLE CASES');

  const cases = SEED_CASES(adminUserId);

  for (const c of cases) {
    const { data: caseData, error } = await supabase
      .from('cases')
      .insert(c)
      .select()
      .single();

    if (error) {
      log(`Case "${c.title.slice(0, 40)}...": ${error.message}`, 'error');
    } else {
      // Add initial timeline entry
      await supabase.from('case_timeline').insert({
        case_id:     caseData.id,
        event_type:  'created',
        description: 'Case created by database seeder',
        actor:       'System Seeder',
        created_at:  new Date().toISOString(),
      });
      log(`Case [${c.severity}] "${c.title.slice(0, 50)}"`, 'success');
    }
  }
}

async function seedPlaybooks(adminUserId) {
  section('SEEDING PLAYBOOKS');

  const playbooks = SEED_PLAYBOOKS(adminUserId);

  for (const pb of playbooks) {
    const { error } = await supabase
      .from('playbooks')
      .insert(pb);

    if (error) {
      log(`Playbook "${pb.title}": ${error.message}`, 'error');
    } else {
      log(`Playbook "${pb.title}" (${pb.steps.length} steps)`, 'success');
    }
  }
}

async function verifyConnection() {
  section('VERIFYING SUPABASE CONNECTION');

  try {
    const { data, error } = await supabase
      .from('tenants')
      .select('count', { count: 'exact', head: true });

    if (error) throw error;
    log(`Supabase connection: OK`, 'success');
    log(`Current tenant count: ${data?.length ?? 0}`, 'info');
    return true;
  } catch (err) {
    log(`Connection failed: ${err.message}`, 'error');
    log('Make sure you have run backend/database/schema.sql in Supabase first!', 'warn');
    return false;
  }
}

// ════════════════════════════════════════════════════════════════
//  MAIN ENTRY POINT
// ════════════════════════════════════════════════════════════════

async function main() {
  console.log('\n');
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║   EYEbot AI — Database Seeder v2.0.0            ║');
  console.log('║   Supabase: ' + process.env.SUPABASE_URL.slice(0, 40) + '  ║');
  console.log('╚══════════════════════════════════════════════════════╝');

  // ── 1. Verify connection ────────────────────────────────────────
  const connected = await verifyConnection();
  if (!connected) {
    console.error('\n❌ Cannot proceed without database connection.\n');
    process.exit(1);
  }

  try {
    // ── 2. Seed tenants (must be first) ──────────────────────────
    await seedTenants();

    // ── 3. Seed users (returns admin profile) ────────────────────
    const users = await seedUsers();
    const adminUser = users.find(u => u.role === 'SUPER_ADMIN');

    if (!adminUser) {
      log('Warning: No SUPER_ADMIN user created. Using fallback ID.', 'warn');
    }

    const adminId = adminUser?.id || null;

    // ── 4. Seed sample data ───────────────────────────────────────
    await seedAlerts(adminId);
    await seedIOCs(adminId);
    await seedCases(adminId);
    await seedPlaybooks(adminId);

    // ── 5. Print credentials summary ─────────────────────────────
    section('SEEDING COMPLETE — LOGIN CREDENTIALS');

    console.log('\n  ┌─────────────────────────────────────────────────────┐');
    SEED_USERS.forEach(u => {
      console.log(`  │  Role:     ${u.role.padEnd(15)}                       │`);
      console.log(`  │  Email:    ${u.email.padEnd(35)}      │`);
      console.log(`  │  Password: ${u.password.padEnd(35)}      │`);
      console.log(`  │  Tenant:   ${Object.entries(TENANT_IDS).find(([,v])=>v===u.tenant_id)?.[0] || 'unknown'}                               │`);
      console.log('  ├─────────────────────────────────────────────────────┤');
    });
    console.log('  └─────────────────────────────────────────────────────┘');

    console.log('\n  ⚠️  IMPORTANT: Change these passwords after first login!');
    console.log('  📖 See PRODUCTION_GUIDE.md for full deployment steps.\n');

  } catch (err) {
    console.error('\n❌ Seeding failed unexpectedly:', err.message);
    console.error(err.stack);
    process.exit(1);
  }
}

// ── Run ──────────────────────────────────────────────────────────
main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
