#!/usr/bin/env node
/**
 * ══════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Seed Script v5.0 (FIXED)
 *  FILE: backend/scripts/seed-mahmoud.js
 *
 *  WHAT THIS SCRIPT DOES:
 *  ─────────────────────
 *  1. Creates/ensures the mssp-global tenant exists in the tenants table
 *  2. Creates Supabase Auth user (Mahmoud Osman) via admin API
 *  3. Creates/updates the users profile row linked to the auth user
 *  4. Creates the second email alias (mahmoud.osman@wadjet.ai)
 *  5. Seeds sample data: alerts, IOCs, cases, playbooks
 *  6. Verifies all required tables exist (schema check)
 *  7. Prints a clean summary with login credentials
 *
 *  HOW TO RUN:
 *  ──────────
 *    cd backend
 *    node scripts/seed-mahmoud.js
 *
 *  REQUIREMENTS:
 *  ─────────────
 *  • backend/.env must have: SUPABASE_URL, SUPABASE_SERVICE_KEY
 *  • Run backend/database/schema.sql in Supabase first (if tables don't exist)
 *
 *  ROOT CAUSE OF OLD ERROR ("Tenant or user not found"):
 *  ──────────────────────────────────────────────────────
 *  The old seed-mahmoud.js used `require('pg')` with `DATABASE_URL` (raw
 *  PostgreSQL driver). This project uses Supabase — there is no DATABASE_URL
 *  in .env. The old script also referenced wrong column names:
 *    - tenants.slug     → should be tenants.short_name
 *    - users.is_active  → should be users.status = 'active'
 *    - user_profiles    → this table doesn't exist; profiles are in users table
 *  This rewrite uses the Supabase JS SDK (same as seed.js), matches the
 *  exact schema.sql column names, and handles all edge cases gracefully.
 * ══════════════════════════════════════════════════════════════════════════
 */

'use strict';

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

/* ═══════════════════════════════════════════════════════
   VALIDATE ENVIRONMENT VARIABLES BEFORE ANYTHING ELSE
═════════════════════════════════════════════════════════ */
const REQUIRED = ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY'];
const missing  = REQUIRED.filter(k => !process.env[k]);
if (missing.length) {
  console.error('\n❌ SEED ERROR: Missing required environment variables:');
  console.error('   ' + missing.join(', '));
  console.error('\n   Fix: Make sure backend/.env contains:');
  console.error('   SUPABASE_URL=https://your-project.supabase.co');
  console.error('   SUPABASE_SERVICE_KEY=eyJh...\n');
  process.exit(1);
}

/* ═══════════════════════════════════════════════════════
   SUPABASE CLIENT — service role (bypasses RLS)
═════════════════════════════════════════════════════════ */
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  {
    auth: { autoRefreshToken: false, persistSession: false },
    db:   { schema: 'public' },
  }
);

/* ═══════════════════════════════════════════════════════
   SEED CONFIGURATION
═════════════════════════════════════════════════════════ */
const TENANT_ID   = '00000000-0000-0000-0000-000000000001'; // Fixed UUID (reproducible)
const TENANT_SLUG = 'mssp-global';

const USERS = [
  {
    email:       'mahmoud@mssp.com',
    password:    'Admin@2024Wadjet!',
    name:        'Mahmoud Osman',
    role:        'SUPER_ADMIN',
    avatar:      'MO',
    permissions: ['read','write','admin','super_admin','manage_tenants','manage_users',
                  'manage_billing','manage_integrations','view_audit_logs',
                  'delete_records','export_data','configure_platform'],
    label:       'Primary Super Admin',
  },
  {
    email:       'mahmoud.osman@wadjet.ai',
    password:    'Admin@2024Wadjet!',
    name:        'Mahmoud Osman',
    role:        'SUPER_ADMIN',
    avatar:      'MO',
    permissions: ['read','write','admin','super_admin','manage_tenants','manage_users',
                  'manage_billing','manage_integrations','view_audit_logs',
                  'delete_records','export_data','configure_platform'],
    label:       'Alt Email Super Admin',
  },
  {
    email:       'analyst@mssp.com',
    password:    'Analyst@Secure2024!',
    name:        'SOC Analyst',
    role:        'ANALYST',
    avatar:      'SA',
    permissions: ['read','write','manage_iocs','manage_cases'],
    label:       'SOC Analyst',
  },
];

/* ═══════════════════════════════════════════════════════
   LOGGING HELPERS
═════════════════════════════════════════════════════════ */
const C = {
  reset:  '\x1b[0m',
  green:  '\x1b[32m',
  red:    '\x1b[31m',
  yellow: '\x1b[33m',
  cyan:   '\x1b[36m',
  bold:   '\x1b[1m',
  dim:    '\x1b[2m',
};

function log(msg, type = 'info') {
  const icons = { info: `${C.cyan}ℹ️ `, success: `${C.green}✅`, error: `${C.red}❌`, warn: `${C.yellow}⚠️ `, step: `${C.dim}▶ ` };
  console.log(`  ${icons[type] || '  '}${C.reset} ${msg}`);
}

function section(title) {
  console.log(`\n${C.bold}${'═'.repeat(58)}${C.reset}`);
  console.log(`${C.bold}  ${title}${C.reset}`);
  console.log(`${'═'.repeat(58)}`);
}

/* ═══════════════════════════════════════════════════════
   STEP 1 — Verify connection + check tables exist
═════════════════════════════════════════════════════════ */
async function verifyConnection() {
  section('STEP 1: Verifying Supabase Connection');

  try {
    const { data, error } = await supabase
      .from('tenants')
      .select('id', { count: 'exact', head: true });

    if (error) {
      if (error.message.includes('does not exist') || error.code === '42P01') {
        log('Table "tenants" does not exist!', 'error');
        log('Run backend/database/schema.sql in Supabase SQL Editor first.', 'warn');
        log('URL: ' + process.env.SUPABASE_URL + '/project/default/sql', 'info');
        return false;
      }
      throw error;
    }

    log(`Supabase connection: OK (${process.env.SUPABASE_URL})`, 'success');
    return true;
  } catch (err) {
    log(`Connection failed: ${err.message}`, 'error');
    log('Verify SUPABASE_URL and SUPABASE_SERVICE_KEY in backend/.env', 'warn');
    return false;
  }
}

/* ═══════════════════════════════════════════════════════
   STEP 2 — Create / ensure tenant exists
═════════════════════════════════════════════════════════ */
async function seedTenant() {
  section('STEP 2: Seeding Tenant');

  const tenantData = {
    id:            TENANT_ID,
    name:          'MSSP Global Operations',
    short_name:    TENANT_SLUG,            // ← correct column name (NOT "slug")
    domain:        'mssp.wadjet.ai',
    plan:          'enterprise',
    risk_level:    'high',
    contact_email: 'admin@mssp.wadjet.ai',
    active:        true,
    settings: {
      alerts_enabled:      true,
      auto_playbooks:      true,
      dark_web_monitoring: true,
    },
  };

  const { data, error } = await supabase
    .from('tenants')
    .upsert(tenantData, { onConflict: 'id' })
    .select('id, name, short_name')
    .single();

  if (error) {
    // Also try upsert on short_name in case UUID conflicts
    const { data: data2, error: err2 } = await supabase
      .from('tenants')
      .upsert(tenantData, { onConflict: 'short_name' })
      .select('id, name, short_name')
      .single();

    if (err2) {
      log(`Tenant upsert failed: ${err2.message}`, 'error');
      // Try a plain select — tenant may already exist
      const { data: existing } = await supabase
        .from('tenants')
        .select('id, name, short_name')
        .eq('short_name', TENANT_SLUG)
        .single();

      if (existing) {
        log(`Tenant already exists: ${existing.name} (${existing.id})`, 'warn');
        return existing.id;
      }
      throw new Error(`Cannot create or find tenant: ${err2.message}`);
    }

    log(`Tenant seeded: ${data2.name} — ID: ${data2.id}`, 'success');
    return data2.id;
  }

  log(`Tenant seeded: ${data.name} — ID: ${data.id}`, 'success');
  return data.id;
}

/* ═══════════════════════════════════════════════════════
   STEP 3 — Create / update Supabase Auth users
═════════════════════════════════════════════════════════ */
async function createAuthUser(user) {
  log(`Processing auth user: ${user.email} [${user.role}]`, 'step');

  // Check if auth user already exists
  const { data: listData, error: listErr } = await supabase.auth.admin.listUsers({ perPage: 1000 });

  if (listErr) {
    log(`Cannot list auth users: ${listErr.message}`, 'warn');
    log('Attempting create anyway...', 'step');
  }

  const existing = listData?.users?.find(u => u.email === user.email);

  if (existing) {
    log(`Auth user already exists (${existing.id}) — updating password`, 'warn');

    // Ensure email is confirmed and password is updated
    const { error: updateErr } = await supabase.auth.admin.updateUserById(existing.id, {
      password:      user.password,
      email_confirm: true,
      user_metadata: {
        name:      user.name,
        role:      user.role,
        tenant_id: TENANT_ID,
      },
    });

    if (updateErr) log(`  Password update warning: ${updateErr.message}`, 'warn');
    else log(`  Auth user updated: confirmed email + new password`, 'success');

    return existing.id;
  }

  // Create new auth user
  const { data: authData, error: authErr } = await supabase.auth.admin.createUser({
    email:           user.email,
    password:        user.password,
    email_confirm:   true,    // Skip email verification
    user_metadata: {
      name:      user.name,
      role:      user.role,
      tenant_id: TENANT_ID,
    },
  });

  if (authErr) {
    // Some errors are non-fatal (user might exist under different UUID)
    log(`  Auth creation warning: ${authErr.message}`, 'warn');

    // Try listing again to find by email
    const { data: retryList } = await supabase.auth.admin.listUsers({ perPage: 1000 });
    const found = retryList?.users?.find(u => u.email === user.email);
    if (found) {
      log(`  Found existing auth user after retry: ${found.id}`, 'warn');
      return found.id;
    }

    throw new Error(`Cannot create auth user for ${user.email}: ${authErr.message}`);
  }

  log(`  Auth user created: ${authData.user.id}`, 'success');
  return authData.user.id;
}

/* ═══════════════════════════════════════════════════════
   STEP 4 — Upsert profile row in public.users table
═════════════════════════════════════════════════════════ */
async function upsertProfile(user, authUserId, tenantId) {
  log(`Upserting profile row: ${user.email}`, 'step');

  const profileData = {
    auth_id:     authUserId,
    tenant_id:   tenantId,
    name:        user.name,
    email:       user.email,
    role:        user.role,
    avatar:      user.avatar,
    permissions: user.permissions,
    status:      'active',       // ← correct column (NOT is_active boolean)
    mfa_enabled: false,
  };

  // Try upsert on auth_id first (cleanest)
  const { data, error } = await supabase
    .from('users')
    .upsert(profileData, { onConflict: 'auth_id' })
    .select('id, email, role, status')
    .single();

  if (error) {
    // auth_id conflict may fail if another row has same email — try email conflict
    const { data: data2, error: err2 } = await supabase
      .from('users')
      .upsert(profileData, { onConflict: 'email' })
      .select('id, email, role, status')
      .single();

    if (err2) {
      // Try a plain update
      const { data: updated, error: updErr } = await supabase
        .from('users')
        .update({
          auth_id:     authUserId,
          role:        user.role,
          permissions: user.permissions,
          status:      'active',
          updated_at:  new Date().toISOString(),
        })
        .eq('email', user.email)
        .select('id, email, role')
        .single();

      if (updErr) {
        log(`  Profile upsert failed: ${err2.message}`, 'error');
        log(`  Update also failed: ${updErr.message}`, 'error');
        return null;
      }

      log(`  Profile updated: ${updated.id} [${updated.role}]`, 'success');
      return updated.id;
    }

    log(`  Profile upserted (by email): ${data2.id} [${data2.role}] — ${data2.status}`, 'success');
    return data2.id;
  }

  log(`  Profile upserted: ${data.id} [${data.role}] — ${data.status}`, 'success');
  return data.id;
}

/* ═══════════════════════════════════════════════════════
   STEP 5 — Seed sample data (alerts, IOCs, etc.)
═════════════════════════════════════════════════════════ */
async function seedSampleData(adminProfileId) {
  section('STEP 5: Seeding Sample Data');

  // ── Alerts ──────────────────────────────────────────────────────
  log('Inserting sample alerts...', 'step');
  const alerts = [
    {
      tenant_id:       TENANT_ID,
      title:           'APT29 C2 Communication Detected',
      description:     'Outbound traffic to known APT29 C2 IP 185.220.101.45 from DESKTOP-A4F2K1. Multiple beaconing attempts detected.',
      severity:        'CRITICAL',
      status:          'open',
      type:            'apt',
      ioc_value:       '185.220.101.45',
      ioc_type:        'ip',
      source:          'EDR',
      mitre_technique: 'T1071.001',
      affected_assets: ['DESKTOP-A4F2K1', '10.0.0.45'],
      metadata:        { confidence: 94, campaign: 'Operation Midnight Rain' },
      created_by:      adminProfileId,
    },
    {
      tenant_id:       TENANT_ID,
      title:           'CVE-2024-3400 Exploit Attempt — PAN-OS RCE',
      description:     'Unauthenticated RCE attempt against perimeter firewall via CVE-2024-3400. CVSS 10.0.',
      severity:        'CRITICAL',
      status:          'in_progress',
      type:            'vulnerability',
      ioc_value:       'CVE-2024-3400',
      ioc_type:        'cve',
      source:          'SIEM',
      mitre_technique: 'T1190',
      affected_assets: ['FW-EDGE-01'],
      metadata:        { cvss: 10.0, patch_available: true },
      created_by:      adminProfileId,
    },
    {
      tenant_id:       TENANT_ID,
      title:           'LSASS Credential Dump — Mimikatz Activity',
      description:     'Suspicious access to lsass.exe memory on SRV-DC-02. Possible credential harvesting via Mimikatz.',
      severity:        'HIGH',
      status:          'open',
      type:            'malware',
      ioc_value:       'lsass.exe',
      ioc_type:        'filename',
      source:          'EDR',
      mitre_technique: 'T1003.001',
      affected_assets: ['SRV-DC-02'],
      metadata:        { process_id: 4821, parent_process: 'cmd.exe' },
      created_by:      adminProfileId,
    },
    {
      tenant_id:       TENANT_ID,
      title:           'LockBit 4.0 Ransomware Binary Detected',
      description:     'LockBit 4.0 hash found on LAPTOP-HR-012. File quarantined by AV. Lateral movement to file server attempted.',
      severity:        'CRITICAL',
      status:          'escalated',
      type:            'ransomware',
      ioc_value:       'a3f2b1c9d4e5f678901234567890abcdef1234567890abcdef1234567890abcd',
      ioc_type:        'hash_sha256',
      source:          'AV',
      mitre_technique: 'T1486',
      affected_assets: ['LAPTOP-HR-012'],
      metadata:        { family: 'LockBit 4.0', quarantined: true },
      created_by:      adminProfileId,
    },
    {
      tenant_id:       TENANT_ID,
      title:           'Lateral Movement — SMB Pass-the-Hash',
      description:     'NTLM pass-the-hash attack detected from compromised workstation to domain controller.',
      severity:        'HIGH',
      status:          'open',
      type:            'lateral_movement',
      ioc_value:       '10.0.1.55',
      ioc_type:        'ip',
      source:          'SIEM',
      mitre_technique: 'T1550.002',
      affected_assets: ['DESKTOP-A4F2K1', 'SRV-DC-02'],
      metadata:        { technique: 'Pass-the-Hash' },
      created_by:      adminProfileId,
    },
  ];

  let alertCount = 0;
  for (const alert of alerts) {
    const { error } = await supabase.from('alerts').insert(alert);
    if (error) {
      // Duplicate or constraint error is OK — skip silently
      if (!error.message.includes('duplicate') && !error.message.includes('unique')) {
        log(`  Alert warning: ${error.message}`, 'warn');
      }
    } else {
      alertCount++;
    }
  }
  log(`Alerts: ${alertCount}/${alerts.length} inserted`, alertCount > 0 ? 'success' : 'warn');

  // ── IOCs ─────────────────────────────────────────────────────────
  log('Inserting sample IOCs...', 'step');
  const iocs = [
    { tenant_id: TENANT_ID, value: '185.220.101.45',           type: 'ip',          reputation: 'malicious', risk_score: 94, source: 'VirusTotal',   country: 'DE', threat_actor: 'APT29',   tags: ['C2','Tor Exit'],               status: 'active', created_by: adminProfileId },
    { tenant_id: TENANT_ID, value: 'maliciousupdate.ru',       type: 'domain',      reputation: 'malicious', risk_score: 89, source: 'AlienVault',   country: 'RU', threat_actor: 'APT29',   tags: ['Phishing','C2'],               status: 'active', created_by: adminProfileId },
    { tenant_id: TENANT_ID, value: 'a3f2b1c9d4e5f678901234567890abcdef1234567890abcdef1234567890abcd', type: 'hash_sha256', reputation: 'malicious', risk_score: 97, source: 'Mandiant', country: null, threat_actor: 'LockBit', tags: ['Ransomware','LockBit 4.0'], status: 'active', created_by: adminProfileId },
    { tenant_id: TENANT_ID, value: '91.243.44.130',             type: 'ip',          reputation: 'malicious', risk_score: 85, source: 'Shodan',       country: 'RU', threat_actor: 'Sandworm', tags: ['C2','Botnet'],               status: 'active', created_by: adminProfileId },
    { tenant_id: TENANT_ID, value: 'update-service-helper.com', type: 'domain',      reputation: 'suspicious', risk_score: 72, source: 'OTX',          country: 'US', threat_actor: null,       tags: ['Suspicious'],               status: 'active', created_by: adminProfileId },
  ];

  let iocCount = 0;
  for (const ioc of iocs) {
    const { error } = await supabase
      .from('iocs')
      .upsert(ioc, { onConflict: 'tenant_id,value' });
    if (error) {
      if (!error.message.includes('duplicate') && !error.message.includes('unique')) {
        log(`  IOC warning: ${error.message}`, 'warn');
      }
    } else {
      iocCount++;
    }
  }
  log(`IOCs: ${iocCount}/${iocs.length} upserted`, iocCount > 0 ? 'success' : 'warn');

  // ── Cases ─────────────────────────────────────────────────────────
  log('Inserting sample cases...', 'step');
  const cases = [
    {
      tenant_id:    TENANT_ID,
      title:        'APT29 Intrusion — Operation Midnight Rain',
      description:  'Active APT29 campaign across 3 endpoints. C2 traffic confirmed. Immediate containment required.',
      severity:     'CRITICAL',
      status:       'in_progress',
      assigned_to:  adminProfileId,
      created_by:   adminProfileId,
      tags:         ['APT29', 'C2', 'Lateral Movement', 'P1'],
      sla_deadline: new Date(Date.now() + 4 * 3600000).toISOString(),
      evidence:     [],
    },
    {
      tenant_id:    TENANT_ID,
      title:        'LockBit Ransomware — LAPTOP-HR-012 Containment',
      description:  'LockBit 4.0 binary detected. HR endpoint isolated. Investigating for lateral spread.',
      severity:     'CRITICAL',
      status:       'open',
      assigned_to:  adminProfileId,
      created_by:   adminProfileId,
      tags:         ['Ransomware', 'LockBit', 'Containment'],
      sla_deadline: new Date(Date.now() + 2 * 3600000).toISOString(),
      evidence:     [],
    },
  ];

  let caseCount = 0;
  for (const c of cases) {
    const { error } = await supabase.from('cases').insert(c);
    if (error) {
      if (!error.message.includes('duplicate') && !error.message.includes('unique')) {
        log(`  Case warning: ${error.message}`, 'warn');
      }
    } else {
      caseCount++;
    }
  }
  log(`Cases: ${caseCount}/${cases.length} inserted`, caseCount > 0 ? 'success' : 'warn');

  // ── Playbooks ─────────────────────────────────────────────────────
  log('Inserting sample playbooks...', 'step');
  const playbooks = [
    {
      tenant_id:        TENANT_ID,
      title:            'Ransomware Initial Response',
      description:      'Immediate containment and investigation steps for ransomware incidents',
      category:         'Ransomware',
      trigger:          'Ransomware IOC detected or file encryption activity observed',
      mitre_techniques: ['T1486', 'T1490', 'T1489'],
      active:           true,
      created_by:       adminProfileId,
      steps: [
        { order: 1, title: 'Isolate Affected Endpoint',   tool: 'edr_isolate',   duration_s: 30,  desc: 'Isolate endpoint via EDR to prevent lateral spread' },
        { order: 2, title: 'Preserve Memory Dump',        tool: 'forensics',     duration_s: 120, desc: 'Capture volatile memory before changes' },
        { order: 3, title: 'Identify Ransomware Family',  tool: 'virustotal',    duration_s: 60,  desc: 'Submit hash to VirusTotal for family ID' },
        { order: 4, title: 'Map to MITRE ATT&CK',         tool: 'mitre_map',     duration_s: 20,  desc: 'Map TTPs to ATT&CK framework' },
        { order: 5, title: 'Verify Backup Integrity',     tool: 'backup_check',  duration_s: 300, desc: 'Verify backups are not affected' },
        { order: 6, title: 'Notify Stakeholders',         tool: 'notify',        duration_s: 10,  desc: 'Alert CISO, legal, and affected team' },
      ],
    },
    {
      tenant_id:        TENANT_ID,
      title:            'Phishing Response Workflow',
      description:      'End-to-end response for confirmed phishing attacks',
      category:         'Phishing',
      trigger:          'Phishing email reported or credential harvesting domain detected',
      mitre_techniques: ['T1566.001', 'T1566.002', 'T1078'],
      active:           true,
      created_by:       adminProfileId,
      steps: [
        { order: 1, title: 'Extract and Analyse IOCs',  tool: 'email_parser',  duration_s: 30, desc: 'Parse email headers, extract URLs' },
        { order: 2, title: 'Enrich Phishing Domain',    tool: 'virustotal',    duration_s: 15, desc: 'Check domain reputation' },
        { order: 3, title: 'Block Malicious Domain',    tool: 'dns_block',     duration_s: 5,  desc: 'Push to DNS blocklist' },
        { order: 4, title: 'Identify Exposed Users',    tool: 'email_search',  duration_s: 60, desc: 'Search for all recipients' },
        { order: 5, title: 'Force Password Reset',      tool: 'ad_reset',      duration_s: 30, desc: 'Reset passwords for affected users' },
        { order: 6, title: 'Submit Takedown Request',   tool: 'abuse_report',  duration_s: 10, desc: 'Report domain to registrar' },
      ],
    },
  ];

  let pbCount = 0;
  for (const pb of playbooks) {
    const { error } = await supabase.from('playbooks').insert(pb);
    if (error) {
      if (!error.message.includes('duplicate') && !error.message.includes('unique')) {
        log(`  Playbook warning: ${error.message}`, 'warn');
      }
    } else {
      pbCount++;
    }
  }
  log(`Playbooks: ${pbCount}/${playbooks.length} inserted`, pbCount > 0 ? 'success' : 'warn');
}

/* ═══════════════════════════════════════════════════════
   STEP 6 — Verify final state
═════════════════════════════════════════════════════════ */
async function verify() {
  section('STEP 6: Verification');

  const tables = ['tenants', 'users', 'alerts', 'iocs', 'cases', 'playbooks'];
  for (const table of tables) {
    const { count, error } = await supabase
      .from(table)
      .select('*', { count: 'exact', head: true });

    if (error) {
      log(`${table}: ${error.message}`, 'warn');
    } else {
      log(`${table}: ${count} rows`, 'info');
    }
  }

  // Check our specific users exist
  const { data: userRows } = await supabase
    .from('users')
    .select('email, role, status, auth_id')
    .in('email', ['mahmoud@mssp.com', 'mahmoud.osman@wadjet.ai', 'analyst@mssp.com']);

  if (userRows?.length) {
    console.log('');
    log('Users in DB:', 'info');
    userRows.forEach(u => {
      const authStatus = u.auth_id ? '🔗 auth linked' : '⚠️  no auth_id';
      log(`  ${u.email} — ${u.role} — ${u.status} — ${authStatus}`, 'step');
    });
  }
}

/* ═══════════════════════════════════════════════════════
   MAIN — orchestrates all steps
═════════════════════════════════════════════════════════ */
async function main() {
  console.log('\n');
  console.log(`${C.bold}╔══════════════════════════════════════════════════════╗${C.reset}`);
  console.log(`${C.bold}║   Wadjet-Eye AI — Seed Script v5.0 (FIXED)          ║${C.reset}`);
  console.log(`${C.bold}║   Supabase: ${process.env.SUPABASE_URL.slice(0, 40).padEnd(40)}   ║${C.reset}`);
  console.log(`${C.bold}╚══════════════════════════════════════════════════════╝${C.reset}`);

  // ── Step 1: Verify connection ─────────────────────────────────────
  const connected = await verifyConnection();
  if (!connected) {
    console.error(`\n${C.red}❌ Cannot proceed — fix Supabase connection first.${C.reset}\n`);
    process.exit(1);
  }

  // ── Step 2: Create/ensure tenant ─────────────────────────────────
  const tenantId = await seedTenant();
  log(`Working with tenant: ${tenantId}`, 'info');

  // ── Steps 3 + 4: Create auth users + profiles ────────────────────
  section('STEPS 3 + 4: Creating Auth Users & Profiles');

  let primaryProfileId = null;
  const results = [];

  for (const user of USERS) {
    try {
      const authUserId    = await createAuthUser(user);
      const profileId     = await upsertProfile(user, authUserId, tenantId);
      results.push({ email: user.email, authUserId, profileId, success: true });
      if (user.email === 'mahmoud@mssp.com') primaryProfileId = profileId;
    } catch (err) {
      log(`Failed to seed ${user.email}: ${err.message}`, 'error');
      results.push({ email: user.email, success: false, error: err.message });
    }
  }

  // ── Step 5: Seed sample data ──────────────────────────────────────
  if (primaryProfileId) {
    await seedSampleData(primaryProfileId);
  } else {
    log('Skipping sample data — no admin profile ID available', 'warn');
  }

  // ── Step 6: Verify ───────────────────────────────────────────────
  await verify();

  // ── Final Summary ─────────────────────────────────────────────────
  section('✅ SEED COMPLETE — LOGIN CREDENTIALS');
  console.log('');
  console.log(`  ${C.bold}┌──────────────────────────────────────────────────────┐${C.reset}`);
  USERS.forEach(u => {
    const result = results.find(r => r.email === u.email);
    const status = result?.success ? `${C.green}✅${C.reset}` : `${C.red}❌${C.reset}`;
    console.log(`  ${C.bold}│${C.reset}  ${status} ${u.label.padEnd(22)}                      ${C.bold}│${C.reset}`);
    console.log(`  ${C.bold}│${C.reset}     Email   : ${u.email.padEnd(40)} ${C.bold}│${C.reset}`);
    console.log(`  ${C.bold}│${C.reset}     Password: ${u.password.padEnd(40)} ${C.bold}│${C.reset}`);
    console.log(`  ${C.bold}│${C.reset}     Role    : ${u.role.padEnd(40)} ${C.bold}│${C.reset}`);
    console.log(`  ${C.bold}├──────────────────────────────────────────────────────┤${C.reset}`);
  });
  console.log(`  ${C.bold}└──────────────────────────────────────────────────────┘${C.reset}`);
  console.log('');
  console.log(`  ${C.yellow}⚠️  IMPORTANT: Change passwords after first login!${C.reset}`);
  console.log(`  ${C.cyan}ℹ️  Frontend: https://wadjet-eye-ai.vercel.app${C.reset}`);
  console.log(`  ${C.cyan}ℹ️  Backend:  ${process.env.SUPABASE_URL}${C.reset}`);
  console.log('');

  // Check for any failures
  const failures = results.filter(r => !r.success);
  if (failures.length > 0) {
    console.log(`  ${C.yellow}⚠️  ${failures.length} user(s) had issues:${C.reset}`);
    failures.forEach(f => console.log(`     ${C.red}• ${f.email}: ${f.error}${C.reset}`));
    console.log('');
    console.log(`  ${C.dim}If auth users exist but profiles failed, run:${C.reset}`);
    console.log(`  ${C.dim}node backend/scripts/seed-mahmoud.js  (safe to re-run)${C.reset}`);
    console.log('');
  }
}

/* ═══════════════════════════════════════════════════════
   RUN
═════════════════════════════════════════════════════════ */
main().catch(err => {
  console.error(`\n${C.red}❌ SEED FATAL ERROR: ${err.message}${C.reset}`);
  console.error(err.stack);

  // Provide helpful diagnosis
  if (err.message.includes('pg') || err.message.includes('DATABASE_URL')) {
    console.error(`\n${C.yellow}HINT: This script uses Supabase SDK, NOT raw PostgreSQL.${C.reset}`);
    console.error(`${C.yellow}      Remove any 'pg' references and ensure .env has SUPABASE_URL.${C.reset}`);
  }
  if (err.message.includes('Cannot find module')) {
    console.error(`\n${C.yellow}HINT: Run 'npm install' in the backend directory first.${C.reset}`);
  }

  process.exit(1);
});
