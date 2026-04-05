-- ══════════════════════════════════════════════════════════════════
--  ThreatPilot AI — EMERGENCY SEED FIX
--  Run this in: Supabase Dashboard → SQL Editor → New Query → Run
--
--  This script:
--  1. Fixes tenant short_name values to match the frontend
--  2. Inserts sample alerts, IOCs, cases, and playbooks
--
--  ⚠️  IMPORTANT: Run backend/scripts/seed.js FIRST to create users.
--      Users cannot be created via SQL (requires Supabase Auth API).
--      After seed.js runs, this script is optional (seed.js inserts all data).
--
--  If seed.js is failing, run this SQL to at least get sample data visible.
-- ══════════════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────
-- STEP 1: Fix tenant short_names
-- ─────────────────────────────────────────────
INSERT INTO public.tenants (id, name, short_name, domain, plan, risk_level, active, settings)
VALUES
  (
    '00000000-0000-0000-0000-000000000001',
    'MSSP Global Operations', 'mssp-global',
    'mssp.threatpilot.ai', 'enterprise', 'high', true,
    '{"alerts_enabled":true,"auto_playbooks":true,"dark_web_monitoring":true}'::jsonb
  ),
  (
    '00000000-0000-0000-0000-000000000002',
    'HackerOne Security', 'hackerone',
    'h1.threatpilot.ai', 'professional', 'medium', true,
    '{"alerts_enabled":true,"auto_playbooks":false,"dark_web_monitoring":true}'::jsonb
  ),
  (
    '00000000-0000-0000-0000-000000000003',
    'Bugcrowd Platform', 'bugcrowd',
    'bc.threatpilot.ai', 'starter', 'low', true,
    '{"alerts_enabled":true,"auto_playbooks":false,"dark_web_monitoring":false}'::jsonb
  )
ON CONFLICT (id) DO UPDATE SET
  short_name = EXCLUDED.short_name,
  name       = EXCLUDED.name,
  settings   = EXCLUDED.settings,
  updated_at = NOW();

-- Verify tenants
SELECT id, name, short_name, plan FROM public.tenants;

-- ─────────────────────────────────────────────
-- STEP 2: Insert sample alerts
-- (uses tenant UUIDs directly — no user FK needed)
-- ─────────────────────────────────────────────

-- Get the MSSP admin user ID (if seed.js was run)
-- If no users exist yet, created_by will be NULL (allowed)
DO $$
DECLARE
  mssp_admin_id UUID;
  h1_admin_id   UUID;
BEGIN
  -- Try to find seeded admin
  SELECT id INTO mssp_admin_id FROM public.users WHERE email = 'mahmoud@mssp.com' LIMIT 1;
  SELECT id INTO h1_admin_id   FROM public.users WHERE email = 'viewer@hackerone.com' LIMIT 1;

  -- ── ALERTS ────────────────────────────────────────────────────
  INSERT INTO public.alerts (tenant_id, title, description, severity, status, type, ioc_value, ioc_type, source, mitre_technique, affected_assets, metadata, created_by)
  VALUES
    (
      '00000000-0000-0000-0000-000000000001',
      'APT29 C2 Communication Detected',
      'Outbound traffic to known APT29 command-and-control IP 185.220.101.45 detected from workstation DESKTOP-A4F2K1. Multiple beaconing attempts over port 443.',
      'CRITICAL', 'open', 'apt', '185.220.101.45', 'ip', 'EDR',
      'T1071.001', ARRAY['DESKTOP-A4F2K1','10.0.0.45'],
      '{"confidence":94,"campaign":"Operation Midnight Rain","kill_chain":"command-and-control"}'::jsonb,
      mssp_admin_id
    ),
    (
      '00000000-0000-0000-0000-000000000001',
      'Critical CVE-2024-3400 Exploit Attempt',
      'PAN-OS GlobalProtect zero-day exploitation attempt detected. Unauthenticated RCE attempt against perimeter firewall. CVSS 10.0.',
      'CRITICAL', 'in_progress', 'vulnerability', 'CVE-2024-3400', 'cve', 'SIEM',
      'T1190', ARRAY['FW-EDGE-01'],
      '{"cvss":10.0,"patch_available":true,"vendor_advisory":"https://security.paloaltonetworks.com/CVE-2024-3400"}'::jsonb,
      mssp_admin_id
    ),
    (
      '00000000-0000-0000-0000-000000000001',
      'LSASS Memory Access — Credential Dump Attempt',
      'Suspicious access to lsass.exe memory detected on domain controller SRV-DC-02. Possible Mimikatz or similar credential harvesting tool.',
      'HIGH', 'open', 'malware', 'lsass.exe', 'filename', 'EDR',
      'T1003.001', ARRAY['SRV-DC-02'],
      '{"process_id":4821,"parent_process":"cmd.exe","user":"SYSTEM"}'::jsonb,
      mssp_admin_id
    ),
    (
      '00000000-0000-0000-0000-000000000001',
      'Ransomware IOC — LockBit 4.0 Binary Hash',
      'LockBit 4.0 ransomware binary SHA256 hash found on endpoint LAPTOP-HR-012. File quarantined. Lateral movement to network shares attempted.',
      'CRITICAL', 'escalated', 'ransomware',
      'a3f2b1c9d4e5f678901234567890abcdef1234567890abcdef1234567890abcd', 'hash_sha256',
      'AV', 'T1486', ARRAY['LAPTOP-HR-012','\\\\SRV-FS-01\\HR'],
      '{"family":"LockBit 4.0","quarantined":true,"ransom_note":true}'::jsonb,
      mssp_admin_id
    ),
    (
      '00000000-0000-0000-0000-000000000002',
      'Phishing Domain — DocuSign Impersonation',
      'Employee clicked link to phishing domain mimicking DocuSign. Credential harvesting page served via HTTPS with valid certificate.',
      'HIGH', 'open', 'phishing', 'docusign-secure-verify.net', 'domain', 'Email Gateway',
      'T1566.002', ARRAY['alice@hackerone.com','bob@hackerone.com'],
      '{"clicked_by":5,"emails_sent":47,"blocked":true,"certificate_issuer":"Let'\''s Encrypt"}'::jsonb,
      h1_admin_id
    ),
    (
      '00000000-0000-0000-0000-000000000001',
      'Lateral Movement — SMB Pass-the-Hash',
      'Pass-the-hash attack detected moving from compromised endpoint to domain controller. NTLM authentication from unusual source.',
      'HIGH', 'open', 'lateral_movement', '10.0.1.55', 'ip', 'SIEM',
      'T1550.002', ARRAY['DESKTOP-A4F2K1','SRV-DC-02'],
      '{"technique":"Pass-the-Hash","source_ip":"10.0.1.55","destination":"SRV-DC-02"}'::jsonb,
      mssp_admin_id
    ),
    (
      '00000000-0000-0000-0000-000000000001',
      'Suspicious PowerShell Execution — Encoded Command',
      'PowerShell launched with Base64-encoded command from Word macro. Possible initial access via malicious document.',
      'MEDIUM', 'open', 'malware', 'powershell.exe', 'filename', 'EDR',
      'T1059.001', ARRAY['WORKSTATION-FIN-07'],
      '{"encoded_command":true,"parent_process":"WINWORD.EXE","network_connection":true}'::jsonb,
      mssp_admin_id
    )
  ON CONFLICT DO NOTHING;

  RAISE NOTICE 'Alerts seeded';

  -- ── IOCs ──────────────────────────────────────────────────────
  INSERT INTO public.iocs (tenant_id, value, type, reputation, risk_score, source, country, asn, threat_actor, tags, status, created_by)
  VALUES
    (
      '00000000-0000-0000-0000-000000000001',
      '185.220.101.45', 'ip', 'malicious', 94,
      'VirusTotal', 'DE', 'AS51167 Contabo GmbH', 'APT29',
      ARRAY['C2','Tor Exit','APT'], 'active', mssp_admin_id
    ),
    (
      '00000000-0000-0000-0000-000000000001',
      'maliciousupdate.ru', 'domain', 'malicious', 89,
      'AlienVault OTX', 'RU', 'AS48666', 'APT29',
      ARRAY['Phishing','C2','Malware Distribution'], 'active', mssp_admin_id
    ),
    (
      '00000000-0000-0000-0000-000000000001',
      'a3f2b1c9d4e5f678901234567890abcdef1234567890abcdef1234567890abcd',
      'hash_sha256', 'malicious', 97,
      'VirusTotal', NULL, NULL, 'LockBit',
      ARRAY['Ransomware','LockBit 4.0'], 'active', mssp_admin_id
    ),
    (
      '00000000-0000-0000-0000-000000000002',
      'docusign-secure-verify.net', 'domain', 'malicious', 88,
      'AbuseIPDB', 'US', 'AS13335 Cloudflare', NULL,
      ARRAY['Phishing','DocuSign'], 'active', h1_admin_id
    ),
    (
      '00000000-0000-0000-0000-000000000001',
      '91.243.44.130', 'ip', 'malicious', 85,
      'Shodan', 'RU', 'AS44050', 'Sandworm',
      ARRAY['C2','Botnet','RU'], 'active', mssp_admin_id
    ),
    (
      '00000000-0000-0000-0000-000000000001',
      'update-service-helper.com', 'domain', 'suspicious', 72,
      'OTX', 'US', 'AS14618 AWS', NULL,
      ARRAY['Suspicious','Newly Registered'], 'active', mssp_admin_id
    )
  ON CONFLICT (tenant_id, value) DO NOTHING;

  RAISE NOTICE 'IOCs seeded';

  -- ── CASES ─────────────────────────────────────────────────────
  INSERT INTO public.cases (tenant_id, title, description, severity, status, assigned_to, created_by, tags, sla_deadline)
  VALUES
    (
      '00000000-0000-0000-0000-000000000001',
      'APT29 Intrusion — Operation Midnight Rain',
      'Active APT29 campaign detected across 3 endpoints. C2 traffic to 185.220.101.45 confirmed. Pass-the-hash lateral movement in progress. Immediate containment required.',
      'CRITICAL', 'in_progress', mssp_admin_id, mssp_admin_id,
      ARRAY['APT29','C2','Lateral Movement','Urgent','P1'],
      NOW() + INTERVAL '4 hours'
    ),
    (
      '00000000-0000-0000-0000-000000000001',
      'LockBit Ransomware — LAPTOP-HR-012 Containment',
      'LockBit 4.0 binary detected and quarantined on LAPTOP-HR-012. HR endpoint isolated from network. Investigating for lateral spread to file servers.',
      'CRITICAL', 'open', mssp_admin_id, mssp_admin_id,
      ARRAY['Ransomware','LockBit','Containment','HR'],
      NOW() + INTERVAL '2 hours'
    ),
    (
      '00000000-0000-0000-0000-000000000002',
      'Phishing Campaign — DocuSign Lure',
      'Targeted spear-phishing campaign against HackerOne employees using DocuSign impersonation. 5 users clicked link. Credential reset and email gateway tuning required.',
      'HIGH', 'open', h1_admin_id, h1_admin_id,
      ARRAY['Phishing','Credential Theft','HR','Awareness'],
      NOW() + INTERVAL '24 hours'
    )
  ON CONFLICT DO NOTHING;

  RAISE NOTICE 'Cases seeded';

  -- ── PLAYBOOKS ─────────────────────────────────────────────────
  INSERT INTO public.playbooks (tenant_id, title, description, category, trigger, mitre_techniques, active, created_by, steps)
  VALUES
    (
      '00000000-0000-0000-0000-000000000001',
      'Ransomware Initial Response',
      'Immediate containment and investigation steps for ransomware incidents. Covers isolation, forensics, family identification, and stakeholder notification.',
      'Ransomware',
      'Ransomware IOC detected or file encryption activity observed',
      ARRAY['T1486','T1490','T1489'],
      true, mssp_admin_id,
      ARRAY[
        '{"order":1,"title":"Isolate Affected Endpoint","tool":"edr_isolate","duration_s":30,"desc":"Immediately isolate endpoint via EDR to prevent lateral spread"}'::jsonb,
        '{"order":2,"title":"Preserve Memory Dump","tool":"forensics","duration_s":120,"desc":"Capture volatile memory before any changes"}'::jsonb,
        '{"order":3,"title":"Identify Ransomware Family","tool":"virustotal","duration_s":60,"desc":"Submit hash to VirusTotal for family identification"}'::jsonb,
        '{"order":4,"title":"Map to MITRE ATT&CK","tool":"mitre_map","duration_s":20,"desc":"Map observed TTPs to ATT&CK framework"}'::jsonb,
        '{"order":5,"title":"Verify Backup Integrity","tool":"backup_check","duration_s":300,"desc":"Verify backup systems are not affected before recovery"}'::jsonb,
        '{"order":6,"title":"Notify Stakeholders","tool":"notify","duration_s":10,"desc":"Alert CISO, legal, and affected business unit"}'::jsonb
      ]
    ),
    (
      '00000000-0000-0000-0000-000000000001',
      'Phishing Response Workflow',
      'End-to-end response for confirmed phishing attacks targeting employees.',
      'Phishing',
      'Employee reports phishing email or credential harvesting domain detected',
      ARRAY['T1566.001','T1566.002','T1078'],
      true, mssp_admin_id,
      ARRAY[
        '{"order":1,"title":"Extract and Analyse IOCs","tool":"email_parser","duration_s":30,"desc":"Parse email headers, extract URLs and attachments"}'::jsonb,
        '{"order":2,"title":"Enrich Phishing Domain","tool":"virustotal","duration_s":15,"desc":"Check domain age, reputation, hosting provider"}'::jsonb,
        '{"order":3,"title":"Block Malicious Domain","tool":"dns_block","duration_s":5,"desc":"Push domain to DNS blocklist"}'::jsonb,
        '{"order":4,"title":"Identify Exposed Users","tool":"email_search","duration_s":60,"desc":"Search email gateway logs for all recipients"}'::jsonb,
        '{"order":5,"title":"Force Password Reset","tool":"ad_reset","duration_s":30,"desc":"Trigger mandatory password reset for affected users"}'::jsonb,
        '{"order":6,"title":"Submit Takedown Request","tool":"abuse_report","duration_s":10,"desc":"Report phishing domain to registrar and hosting provider"}'::jsonb
      ]
    ),
    (
      '00000000-0000-0000-0000-000000000001',
      'Malicious IP Investigation',
      'Enrichment and response workflow for suspicious or malicious IPs.',
      'Network Scanning',
      'IP with risk score > 80 detected in network traffic',
      ARRAY['T1071.001','T1095','T1571'],
      true, mssp_admin_id,
      ARRAY[
        '{"order":1,"title":"WHOIS Lookup","tool":"whois_lookup","duration_s":5,"desc":"Identify IP registration and abuse contacts"}'::jsonb,
        '{"order":2,"title":"VirusTotal Check","tool":"virustotal","duration_s":10,"desc":"Check detection ratio across 70+ AV engines"}'::jsonb,
        '{"order":3,"title":"AbuseIPDB Reputation","tool":"abuseipdb","duration_s":8,"desc":"Check community abuse reports and confidence score"}'::jsonb,
        '{"order":4,"title":"Shodan Port Scan","tool":"shodan_query","duration_s":15,"desc":"Identify open ports, services, and known CVEs"}'::jsonb,
        '{"order":5,"title":"OTX Threat Intelligence","tool":"otx_pulse","duration_s":10,"desc":"Check AlienVault OTX pulse data"}'::jsonb,
        '{"order":6,"title":"Firewall Block Rule","tool":"firewall_block","duration_s":5,"desc":"Push automatic block rule to perimeter firewall"}'::jsonb
      ]
    )
  ON CONFLICT DO NOTHING;

  RAISE NOTICE 'Playbooks seeded';

END $$;

-- ─────────────────────────────────────────────
-- STEP 3: Verify row counts
-- ─────────────────────────────────────────────
SELECT
  'tenants'   AS "table", COUNT(*) AS rows FROM public.tenants
UNION ALL SELECT 'users',     COUNT(*) FROM public.users
UNION ALL SELECT 'alerts',    COUNT(*) FROM public.alerts
UNION ALL SELECT 'iocs',      COUNT(*) FROM public.iocs
UNION ALL SELECT 'cases',     COUNT(*) FROM public.cases
UNION ALL SELECT 'playbooks', COUNT(*) FROM public.playbooks
ORDER BY "table";
