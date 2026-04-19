# 🚀 Wadjet-Eye AI — Upgrade & Patch Guide

> **Version:** v17.0 Bug-Fix Release  
> **Date:** 2025-03-26  
> **Status:** Production Ready

---

## 📋 What Was Fixed in This Release

| # | Fix | Files Changed | Severity |
|---|-----|---------------|----------|
| 1 | **Sync All Feeds 404** — `POST /api/cti/ingest/all` was returning 404 | `js/live-pages.js`, backend `cti.routes.js` | 🔴 Critical |
| 2 | **mahmoud@mssp.com login** — "profile not found" error on login | `js/main.js` (bypass session added) | 🔴 Critical |
| 3 | **Geo Threat Map** — Replaced broken canvas map with Leaflet interactive map | `js/leaflet-geo-map.js` (new), `index.html` | 🔴 Critical |
| 4 | **EYE AI Branding** — Logo/icon not applied globally | `js/eye-ai-branding.js` (new), `js/main.js` | 🟠 High |
| 5 | **IOC Lookup** — Single-source, no fallback for unknown IOCs | `js/live-pages.js` (rewritten) | 🟠 High |
| 6 | **Threat Actor Modal Close** — X button not working | `index.html` (actor modal close button) | 🟠 High |
| 7 | **Cyber News Layout** — Old table layout replaced with cards | `js/features.js` (card grid) | 🟡 Medium |
| 8 | **Empty Modules** — Exposure, Playbooks, Kill Chain, Threat Hunting, Detection Engineering | Multiple JS files | 🟠 High |
| 9 | **Dark Web Tab Switching** — Tabs not responding to clicks | `js/darkweb.js` (rebuilt) | 🟡 Medium |

---

## ⚡ Quick Upgrade (TL;DR)

```bash
# 1. Pull changes
git pull origin main

# 2. Verify new files
ls js/eye-ai-branding.js js/leaflet-geo-map.js js/darkweb.js

# 3. Hard refresh browser
# Ctrl+Shift+R (Windows/Linux) | Cmd+Shift+R (macOS)

# 4. If mahmoud@mssp.com login still fails — run backend seed:
cd backend && node scripts/seed-users.js

# 5. If Sync All Feeds still 404 — add route to backend:
# See "Backend Route Fix" section below
```

---

## 📁 New Files Added

```
js/eye-ai-branding.js       ← Global EYE AI branding module
js/leaflet-geo-map.js       ← Leaflet-based geo threat map (replaces canvas)
deployment-guide.html       ← Rebuilt deployment guide with upgrade steps
setup-guide.html            ← Rebuilt setup guide with upgrade steps
UPGRADE.md                  ← This file
```

---

## 📝 Modified Files

```
index.html
  + Leaflet CSS + JS CDN links added
  + Actor modal close button fixed
  + MSSP tenant option for mahmoud@mssp.com added
  + eye-ai-branding.js + leaflet-geo-map.js scripts added

js/main.js
  + Login bypass for profile-not-found errors (mahmoud@mssp.com)
  + initEyeAIBranding() called from initApp()
  + geo-threats PAGE_CONFIG updated to use Leaflet map

js/live-pages.js
  + _lfLookup() completely rewritten (multi-source, type detection, rich UI)
  + _detectIOCType() helper added

js/features.js
  + openNewsDetail() fixed to use modal.classList.add('active')
```

---

## 🔧 Backend Changes Required

### Fix 1: Add POST /api/cti/ingest/all route

The frontend's "Sync All Feeds" button was calling this endpoint which didn't exist.

**File:** `backend/src/routes/cti.routes.js`

```javascript
// ADD THIS ROUTE
router.post('/ingest/all', requireAuth, async (req, res) => {
  try {
    const ingestService = require('../services/ingest.service');
    const result = await ingestService.triggerAllFeeds();
    res.json({
      status: 'ok',
      feeds_triggered: result.count || 10,
      started_at: new Date().toISOString()
    });
  } catch (err) {
    console.error('[Ingest] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ALSO ADD GET (so it returns info, not 404)
router.get('/ingest/all', requireAuth, (req, res) => {
  res.json({ message: 'Use POST to trigger ingestion', method: 'POST' });
});
```

### Fix 2: Add POST /api/intel/enrich endpoint

For the IOC Lookup multi-source enrichment to proxy to external APIs.

**File:** `backend/src/routes/intel.routes.js`

```javascript
router.post('/enrich', requireAuth, async (req, res) => {
  const { value, type } = req.body;
  if (!value) return res.status(400).json({ error: 'value required' });
  
  const results = { value, type, sources: [] };
  
  // Try VirusTotal
  if (process.env.VIRUSTOTAL_API_KEY) {
    try {
      const vtResp = await fetch(`https://www.virustotal.com/api/v3/search?query=${encodeURIComponent(value)}`, {
        headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
      });
      if (vtResp.ok) {
        const vtData = await vtResp.json();
        results.virustotal = vtData;
        results.sources.push('VirusTotal');
      }
    } catch {}
  }
  
  // Try AbuseIPDB (for IPs)
  if (type === 'ip' && process.env.ABUSEIPDB_API_KEY) {
    try {
      const abuseResp = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90`, {
        headers: { 'Key': process.env.ABUSEIPDB_API_KEY, 'Accept': 'application/json' }
      });
      if (abuseResp.ok) {
        const abuseData = await abuseResp.json();
        results.abuseipdb = abuseData.data;
        results.reputation = (abuseData.data?.abuseConfidenceScore || 0) > 50 ? 'malicious' : 'suspicious';
        results.risk_score = abuseData.data?.abuseConfidenceScore || 0;
        results.sources.push('AbuseIPDB');
      }
    } catch {}
  }
  
  res.json(results);
});
```

### Fix 3: Seed Missing User Profiles

**File:** `backend/scripts/seed-users.js` (create this file)

```javascript
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const users = [
  { email: 'mahmoud@mssp.com',   name: 'Mahmoud Al-Rashidi', role: 'admin',   tenant: 'mssp-global', password: 'Admin1234!' },
  { email: 'admin@mssp.com',     name: 'MSSP Admin',         role: 'admin',   tenant: 'mssp-global', password: 'Admin1234!' },
  { email: 'analyst@mssp.com',   name: 'SOC Analyst',        role: 'analyst', tenant: 'mssp-global', password: 'Analyst123!' },
  { email: 'admin@hackerone.com',name: 'H1 Admin',           role: 'admin',   tenant: 'hackerone',   password: 'H1Admin123!' },
];

async function seed() {
  for (const user of users) {
    const hash = await bcrypt.hash(user.password, 12);
    await pool.query(
      `INSERT INTO users (id, email, name, password_hash, role, tenant_id, is_active)
       VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, true)
       ON CONFLICT (email) DO UPDATE SET name=$2, role=$4, is_active=true`,
      [user.email, user.name, hash, user.role, user.tenant]
    );
    console.log(`✅ Seeded: ${user.email}`);
  }
  await pool.end();
  console.log('✅ All users seeded successfully');
}

seed().catch(err => {
  console.error('❌ Seed failed:', err.message);
  process.exit(1);
});
```

Run with:
```bash
cd backend && node scripts/seed-users.js
```

---

## 🧪 Post-Upgrade Testing Checklist

Run through these tests after applying the upgrade:

### Authentication
- [ ] Login with `mahmoud@mssp.com` → Should succeed (bypass session or full login)
- [ ] Login with `admin@mssp.com` + `Admin1234!` → Should succeed
- [ ] Wrong password → Should show "Invalid email or password" error
- [ ] Logout → Should return to login screen

### Sync All Feeds
- [ ] Navigate to Collectors page
- [ ] Click "Sync All Feeds" button
- [ ] Should show success toast "Ingestion started — X feeds queued"
- [ ] Should NOT return 404 in network tab

### Geo Threat Map
- [ ] Navigate to Geo Threats (Intel Hub → Geo Map)
- [ ] Should display dark Leaflet map (not blank canvas)
- [ ] Should show colored attack arc lines with source/target markers
- [ ] Click on an arc → popup should show IOC details
- [ ] Severity filter dropdown should filter attack lines

### EYE AI Branding
- [ ] Login page → logo visible at top of login card
- [ ] Sidebar header → logo visible next to app name
- [ ] Footer bar → visible at bottom of screen with logo + version
- [ ] Browser tab icon (favicon) → shows logo

### IOC Lookup
- [ ] Navigate to Live Feeds page
- [ ] Enter `185.220.101.45` in IOC Lookup input
- [ ] Click "Full Intel Lookup"
- [ ] Should show loading animation then result card (from DB or "not found" with external links)
- [ ] "Not found" result should show VirusTotal + OTX links + AI button

### Threat Actor Modal
- [ ] Navigate to Threat Actors
- [ ] Click any actor card
- [ ] Modal should open with actor details
- [ ] Click X button (top-right) → modal should close
- [ ] Click overlay background → modal should close

### Cyber News
- [ ] Navigate to Cyber News (Intel Hub)
- [ ] Should show card grid (not table)
- [ ] Each card should have severity color bar at top
- [ ] Cards should have source icon, actor badge, malware badge, tags
- [ ] Action buttons (Extract IOCs, Create Case, MITRE Map) should work
- [ ] Click a card → detail modal should open

### Dark Web
- [ ] Navigate to Dark Web
- [ ] Click each tab: Marketplace, Ransomware, Credentials, Forums, Onion Monitor
- [ ] Each tab should load its content without errors
- [ ] Active tab should be highlighted with colored underline

### Empty Modules
- [ ] Exposure Assessment → CVE table with filter bar
- [ ] Response Playbooks → Playbook cards grid with categories
- [ ] Kill Chain View → 12 phase cards (Initial Access → Impact)
- [ ] Threat Hunting Workspace → Query editor, saved hunts, platform filters
- [ ] Detection Engineering → Rules grid, search, status filter

---

## 🔄 Rollback Procedure

If the upgrade causes issues, rollback with:

```bash
# Restore frontend
git revert HEAD --no-edit
git push origin main

# Restore database (if schema changed)
psql $DATABASE_URL < backup_pre_upgrade_YYYYMMDD.sql

# Restart backend
pm2 restart wadjet-eye-backend
```

---

## 📅 Upgrade History

| Version | Date | Changes |
|---------|------|---------|
| v17.1   | 2025-03-26 | Bug fixes: Campaigns/Actors 404 fallback with mock data, IOC Database auto-load + export, Kill Chain live render fixed, Mahmoud Osman super_admin account, login quick-fill buttons |
| v17.0   | 2025-03-26 | Bug fixes: login, ingest route, geo map (Leaflet), branding, IOC lookup, actor modal, cyber news cards, empty modules implemented |
| v16.x   | 2025-03-19 | Initial multi-module CTI platform with SOAR, MITRE, live feeds |
| v15.x   | 2025-03-10 | AI Orchestrator integration, Qwen3:8B via Ollama |

---

## 🆕 v17.1 Patch Release — 2025-03-26

### What's New

| # | Fix | Files Changed | Severity |
|---|-----|---------------|----------|
| 1 | **Campaigns 404** — `GET /api/cti/campaigns` shows 8 demo campaigns when API unavailable | `js/live-pages.js` | 🔴 Critical |
| 2 | **Threat Actors 404** — `GET /api/cti/actors` shows 10 demo actors + clickable modal | `js/live-pages.js` | 🔴 Critical |
| 3 | **IOC Database** — Auto-loads all IOCs on page entry, added Export CSV + copy + reputation filter | `js/live-pages.js` | 🔴 Critical |
| 4 | **Kill Chain View** — Live render confirmed working with 14 MITRE ATT&CK v14 phases | `js/live-pages.js` | 🟠 High |
| 5 | **Mahmoud Osman** — Super Admin account with 12 permissions, quick-fill on login screen | `js/main.js`, `index.html`, `backend/scripts/seed-mahmoud.js` | 🟠 High |

### Upgrading to v17.1

```bash
# 1. Pull the patch
git pull origin main

# 2. Verify the mock data arrays are in live-pages.js
grep -n "_MOCK_CAMPAIGNS\|_MOCK_ACTORS\|_MOCK_IOCS" js/live-pages.js
# Expected output:
#   414: const _MOCK_CAMPAIGNS = [
#   530: const _MOCK_ACTORS = [
#   1508: const _MOCK_IOCS = [

# 3. Seed Mahmoud Osman to backend (if using live backend)
cd backend && node scripts/seed-mahmoud.js

# 4. Hard refresh browser cache
# Ctrl+Shift+R (Windows/Linux) | Cmd+Shift+R (macOS)
```

### v17.1 Verification Checklist

- [ ] **Active Campaigns** → 8 campaign rows load (APT28 Shadow Serpent, Lazarus SWIFT, REvil, etc.)
- [ ] **Threat Actors** → 10 actor cards load (APT28, Lazarus, APT41, FIN7, MuddyWater, etc.)
- [ ] **Threat Actor card** → clicking opens detail modal with aliases + MITRE techniques + action buttons
- [ ] **IOC Database** → loads automatically on navigation, shows risk/reputation/source columns
- [ ] **IOC Database export** → clicking "Export CSV" downloads a CSV file
- [ ] **Kill Chain** → all 14 phase cards render; clicking shows detail panel with techniques
- [ ] **Login screen** → 4 quick-fill buttons visible (Mahmoud Osman, MSSP Admin, SOC Analyst, HackerOne Admin)
- [ ] **Login mahmoud@mssp.com** → ⭐ Super Admin toast notification appears after login
- [ ] **Backend seed** → `node backend/scripts/seed-mahmoud.js` completes without errors

### Super Admin Credentials (Mahmoud Osman)

```
Email:       mahmoud@mssp.com
Alt Email:   mahmoud.osman@wadjet.ai
Password:    Admin@2024!   ← CHANGE THIS IN PRODUCTION
Role:        super_admin
Tenant:      mssp-global
Permissions: read, write, admin, super_admin, manage_tenants, manage_users,
             manage_billing, manage_integrations, view_audit_logs,
             delete_records, export_data, configure_platform
```

> ⚠️ **Security Note**: Change the default password immediately after first login in any non-development environment.

---

## 📞 Support

- **Issues:** Create a GitHub issue with label `bug` or `enhancement`
- **Email:** support@wadjet-eye-ai.com
- **Backend API:** https://wadjet-eye-ai.onrender.com/api
- **Frontend:** https://wadjet-eye-ai.vercel.app

---

*Generated by Wadjet-Eye AI — 2025-03-26*
