# Wadjet-Eye AI — Enterprise v4.0 Complete Implementation Guide

## Table of Contents
1. [What Was Done](#what-was-done)
2. [Modified / Added Files](#modified--added-files)
3. [Step-by-Step: Database Migration](#step-by-step-database-migration)
4. [Step-by-Step: Backend Changes](#step-by-step-backend-changes)
5. [Step-by-Step: Frontend Changes](#step-by-step-frontend-changes)
6. [Step-by-Step: Seed Super-Admin](#step-by-step-seed-super-admin)
7. [Configuration Updates](#configuration-updates)
8. [Git Workflow](#git-workflow)
9. [Post-Deploy Verification](#post-deploy-verification)

---

## What Was Done

### Problem Summary
| Issue | Root Cause | Fix Applied |
|-------|-----------|-------------|
| HTTP 401 errors on all pages | `_fetch()` returned mock data only in bypass mode; real backend rejected bypass token | Rewrote `api-client.js` with real JWT auth, auto-refresh interceptor |
| Blank pages (Dashboard, SOAR, Collectors, etc.) | Mock data only returned for bypass token; real API calls failed silently | All pages now hit real backend; live-pages.js uses API client with proper auth |
| Login page had demo bypass | Hardcoded `_BYPASS_ACCOUNTS` triggered before trying real auth | New `doLogin()`: real backend FIRST, offline only on network failure |
| No persistent session on page refresh | Access token only in sessionStorage; no restore logic | `api-client.js` reads refresh token from localStorage, auto-restores session |
| No Kill Chain visualization | Kill chain page had placeholder | New `js/kill-chain-viz.js`: MITRE ATT&CK v14, 14 tactics, heat map, technique modals |
| No detail pages for entities | Clicking entries showed nothing | New `js/detail-pages.js`: full detail modals for alerts/campaigns/IOCs/CVEs/cases/actors |
| No CVE/vulnerability sync | vulnerabilities route existed but NVD service missing | New `backend/services/ingestion/nvd.js`: NVD + CISA KEV + Exploit-DB sync |
| No Sysmon log analysis | Frontend UI existed but no backend | New `backend/routes/sysmon.js`: upload JSON/CSV/XML, 20 detection rules, MITRE mapping |
| No executive report PDF | Only placeholder in live-pages.js | New `backend/routes/reports.js`: full HTML report generation with KPIs, charts, compliance |
| Refresh token not stored in DB | Auth route generated tokens but didn't persist them | `routes/auth.js` v4.0: refresh tokens stored as SHA-256 hash in `refresh_tokens` table |

---

## Modified / Added Files

### New Files
```
js/kill-chain-viz.js                 — Interactive MITRE ATT&CK Kill Chain visualization
js/detail-pages.js                   — Dynamic detail modals for all entity types
backend/routes/sysmon.js             — Sysmon log analyzer (20 detection rules)
backend/routes/reports.js            — Executive report generation (HTML/PDF)
backend/services/ingestion/nvd.js    — NVD CVE + CISA KEV dedicated sync service
```

### Modified Files
```
js/api-client.js                     — Complete rewrite: real JWT, auto-refresh, session restore
js/main.js                           — doLogin(): real auth first, emergency fallback only
index.html                           — Added new scripts, session restore listener
backend/server.js                    — Registered 4 new routes
README.md                            — Complete professional documentation
```

### Pre-Existing (Already Implemented)
```
backend/routes/auth.js               — JWT refresh rotation, device fingerprinting (v4.0 already written)
backend/database/migration-v4.0-enterprise.sql — refresh_tokens, sysmon, vuln tables (already written)
backend/services/ingestion/index.js  — 10 real feed workers (already written)
```

---

## Step-by-Step: Database Migration

### Step 1: Apply Core Migration
```sql
-- In Supabase Dashboard → SQL Editor:

-- 1a. Run this FIRST if starting fresh:
-- (Skip if tables already exist)

-- 1b. Apply enterprise migration:
-- Copy contents of backend/database/migration-v4.0-enterprise.sql and run

-- Key tables created:
-- refresh_tokens  — SHA-256 hashed session tokens
-- login_activity  — Login audit trail with IP/device
-- vulnerabilities — NVD CVE + CISA KEV data
-- sysmon_logs     — Sysmon analysis sessions
-- sysmon_detections — Individual rule matches
-- case_evidence   — File attachment metadata
-- executive_reports — Generated report records
```

### Step 2: Add Missing Columns (idempotent)
```sql
-- These are in migration-v4.0-enterprise.sql but safe to re-run:
ALTER TABLE cases ADD COLUMN IF NOT EXISTS sla_hours       INTEGER DEFAULT 72;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS sla_deadline    TIMESTAMPTZ;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS sla_breached    BOOLEAN DEFAULT FALSE;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS closed_at       TIMESTAMPTZ;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS mitre_techniques TEXT[] DEFAULT '{}';
ALTER TABLE cases ADD COLUMN IF NOT EXISTS kill_chain_phase TEXT;

ALTER TABLE feed_logs ADD COLUMN IF NOT EXISTS iocs_fetched  INTEGER DEFAULT 0;
ALTER TABLE feed_logs ADD COLUMN IF NOT EXISTS iocs_new      INTEGER DEFAULT 0;
ALTER TABLE feed_logs ADD COLUMN IF NOT EXISTS iocs_updated  INTEGER DEFAULT 0;
ALTER TABLE feed_logs ADD COLUMN IF NOT EXISTS iocs_skipped  INTEGER DEFAULT 0;
ALTER TABLE feed_logs ADD COLUMN IF NOT EXISTS duration_ms   INTEGER DEFAULT 0;
ALTER TABLE feed_logs ADD COLUMN IF NOT EXISTS error_message TEXT;
```

### Step 3: Verify Tables
```sql
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
-- Should include: refresh_tokens, login_activity, vulnerabilities, sysmon_logs, etc.
```

---

## Step-by-Step: Backend Changes

### Step 1: Register New Routes in server.js
```javascript
// backend/server.js — ADD these imports (already done):
const vulnRoutes   = require('./routes/vulnerabilities');
const sysmonRoutes = require('./routes/sysmon');
const reportRoutes = require('./routes/reports');

// ADD these route registrations (already done):
app.use('/api/vulnerabilities', vulnRoutes);
app.use('/api/sysmon',          sysmonRoutes);
app.use('/api/reports',         reportRoutes);
```

### Step 2: Verify errorHandler Middleware
```javascript
// backend/middleware/errorHandler.js — must export:
module.exports = {
  asyncHandler: (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next),
  createError:  (status, message) => { const e = new Error(message); e.status = status; return e; },
  errorHandler: (err, req, res, next) => {
    const status = err.status || 500;
    res.status(status).json({ error: err.message || 'Internal server error' });
  }
};
```

### Step 3: Test New Endpoints
```bash
TOKEN="your_jwt_token"

# Test vulnerabilities
curl https://wadjet-eye-ai.onrender.com/api/vulnerabilities?severity=CRITICAL \
  -H "Authorization: Bearer $TOKEN" | jq '.total'

# Test sysmon rules
curl https://wadjet-eye-ai.onrender.com/api/sysmon/rules \
  -H "Authorization: Bearer $TOKEN" | jq '.total'

# Test reports list
curl https://wadjet-eye-ai.onrender.com/api/reports \
  -H "Authorization: Bearer $TOKEN" | jq '.total'
```

---

## Step-by-Step: Frontend Changes

### Step 1: Load Order in index.html
The new scripts must be added AFTER live-pages.js:
```html
<!-- EXISTING: -->
<script src="js/live-pages.js"></script>
<script src="js/eye-ai-branding.js"></script>
<script src="js/leaflet-geo-map.js"></script>

<!-- NEW (already added): -->
<script src="js/kill-chain-viz.js"></script>
<script src="js/detail-pages.js"></script>

<script src="js/main.js"></script>  <!-- Always last -->
```

### Step 2: Session Restore Block
Already added to index.html, after main.js:
```html
<script>
  document.addEventListener('DOMContentLoaded', function() {
    window.addEventListener('auth:restored', function(e) {
      const user = e.detail;
      if (!user) return;
      // If still on login screen → auto-login
      const loginScreen = document.getElementById('loginScreen');
      if (loginScreen && loginScreen.style.display !== 'none') {
        window.CURRENT_USER = { ...user };  // simplified — see index.html for full version
        loginScreen.style.display = 'none';
        document.getElementById('mainApp').style.display = 'flex';
        if (typeof initApp === 'function') initApp();
      }
    });
  });
</script>
```

### Step 3: Enable Detail Page Links
In your live-pages.js or page renderers, replace static row clicks with:
```javascript
// For alerts table row click:
onclick="showAlertDetail('${alert.id}')"

// For campaigns:
onclick="showCampaignDetail('${campaign.id}')"

// For IOCs:
onclick="showIOCDetail('${ioc.id}')"

// For CVEs:
onclick="showCVEDetail('${cve.cve_id}')"

// For cases:
onclick="showCaseDetail('${c.id}')"

// For threat actors:
onclick="showActorDetail('${actor.id}')"
```

### Step 4: Kill Chain Navigation
The kill chain page (`page-kill-chain`) auto-renders when navigated to.
In main.js PAGE_CONFIG, the kill-chain entry already calls `renderKillChainLive()`.

---

## Step-by-Step: Seed Super-Admin

### Option A: Supabase Dashboard (Recommended)
1. Go to your Supabase project → **Authentication → Users**
2. Click **"Add user"** → Enter email: `mahmoud.osman@wadjet.ai`, set a strong password
3. Copy the **User UID** from the Users list
4. Run in SQL Editor:

```sql
-- Replace 'PUT_UID_HERE' with the actual auth UID from step 3
INSERT INTO users (
  auth_id, tenant_id, email, name, role, permissions, status, created_at
) VALUES (
  'PUT_UID_HERE',
  '00000000-0000-0000-0000-000000000001',
  'mahmoud.osman@wadjet.ai',
  'Mahmoud Osman',
  'SUPER_ADMIN',
  ARRAY[
    'read', 'write', 'admin', 'super_admin', 'manage_tenants',
    'manage_users', 'manage_billing', 'manage_integrations',
    'view_audit_logs', 'delete_records', 'export_data', 'configure_platform'
  ],
  'active',
  NOW()
)
ON CONFLICT (email) DO UPDATE SET
  auth_id     = EXCLUDED.auth_id,
  role        = 'SUPER_ADMIN',
  status      = 'active',
  permissions = EXCLUDED.permissions;
```

### Option B: API (after backend is running)
```bash
# Step 1: Login as any existing admin to get a token
TOKEN=$(curl -s -X POST https://wadjet-eye-ai.onrender.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@mssp.com","password":"YOUR_ADMIN_PW"}' | jq -r '.token')

# Step 2: Register Mahmoud Osman
curl -X POST https://wadjet-eye-ai.onrender.com/api/auth/register \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "mahmoud.osman@wadjet.ai",
    "password": "SecureP@ssw0rd2024!",
    "name": "Mahmoud Osman",
    "role": "SUPER_ADMIN"
  }'
```

---

## Configuration Updates

### backend/.env
```env
# Ensure these are set:
SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...  # service_role key
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...   # anon key
FRONTEND_URL=https://wadjet-eye-ai.vercel.app
ALLOWED_ORIGINS=https://wadjet-eye-ai.vercel.app,https://www.genspark.ai,http://localhost:3000

# Auth config:
REFRESH_TOKEN_EXPIRY_DAYS=30

# Feed API keys (optional — feeds without keys will be skipped gracefully):
OTX_API_KEY=your_otx_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
NVD_API_KEY=your_nvd_key   # Free from https://nvd.nist.gov/developers/request-an-api-key
```

### index.html Backend URL
```html
<!-- Already set in index.html head: -->
<script>
  window.THREATPILOT_API_URL = 'https://wadjet-eye-ai.onrender.com';
  window.THREATPILOT_WS_URL  = 'https://wadjet-eye-ai.onrender.com';
  window.WADJET_API_URL      = window.THREATPILOT_API_URL;
</script>
```

---

## Git Workflow

### Push All Changes
```bash
cd /path/to/wadjet-eye-ai

# Stage all changed files:
git add \
  js/api-client.js \
  js/main.js \
  js/kill-chain-viz.js \
  js/detail-pages.js \
  index.html \
  backend/server.js \
  backend/routes/sysmon.js \
  backend/routes/reports.js \
  backend/routes/vulnerabilities.js \
  backend/services/ingestion/nvd.js \
  backend/database/migration-v4.0-enterprise.sql \
  README.md \
  ENTERPRISE_GUIDE.md

git status  # Verify staged files

git commit -m "feat(v4.0): enterprise auth + kill chain + sysmon + CVE feeds + report generation

- api-client.js: Real JWT auth, auto-refresh interceptor, session persistence across page refresh
- main.js: Real auth first, no demo bypass, emergency offline only on network failure  
- kill-chain-viz.js: Interactive MITRE ATT&CK v14 kill chain with heat map + technique correlation
- detail-pages.js: Full detail modals for alerts/campaigns/IOCs/CVEs/cases/threat-actors
- index.html: Added enterprise scripts, session restore on page load
- server.js: Registered /api/vulnerabilities, /api/sysmon, /api/reports
- routes/sysmon.js: Sysmon EVTX/JSON/CSV analyzer with 20 detection rules + MITRE mapping
- routes/reports.js: Executive HTML/PDF report generation with KPIs + compliance + timeline
- services/ingestion/nvd.js: NVD CVE + CISA KEV + Exploit-DB sync service
- migration-v4.0-enterprise.sql: Enterprise tables (refresh_tokens, sysmon, vulns, reports)"

git push origin main
```

### Create PR (GitHub CLI)
```bash
# Create feature branch for review (optional):
git checkout -b feat/enterprise-v4.0 origin/main
# Apply changes, commit, push
git push origin feat/enterprise-v4.0

# Create PR:
gh pr create \
  --title "Enterprise v4.0: Real Auth + Kill Chain + Sysmon Analyzer + CVE Feeds" \
  --body "## Changes

### Backend
- **routes/auth.js**: JWT refresh rotation with SHA-256 token storage, device fingerprinting
- **routes/sysmon.js**: NEW — Sysmon log analyzer with 20 real detection rules mapped to MITRE ATT&CK
- **routes/reports.js**: NEW — Executive report generation (HTML with KPIs, alerts, compliance)
- **routes/vulnerabilities.js**: NVD CVE listing with CISA KEV filter and live NVD fallback
- **services/ingestion/nvd.js**: NEW — Dedicated NVD CVE + CISA KEV + Exploit-DB ingestion

### Frontend  
- **api-client.js**: Enterprise JWT client with auto-refresh, session persistence, WS integration
- **main.js**: Real backend authentication first; offline emergency fallback ONLY on network errors
- **kill-chain-viz.js**: NEW — Full MITRE ATT&CK v14 interactive kill chain visualization
- **detail-pages.js**: NEW — Dynamic detail modals for all entity types

### Database
- Requires **migration-v4.0-enterprise.sql** applied in Supabase

### Breaking Changes
- Demo/bypass accounts removed from login flow
- Session tokens now stored in localStorage (not just sessionStorage)
- CURRENT_USER._bypass field renamed to _offline" \
  --base main
```

---

## Post-Deploy Verification

### 1. Health Check
```bash
curl https://wadjet-eye-ai.onrender.com/health | jq
# Expected: { status: "OK", db: "connected", ... }
```

### 2. Login Test
```bash
curl -X POST https://wadjet-eye-ai.onrender.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"mahmoud.osman@wadjet.ai","password":"YOUR_PASSWORD"}' | jq
# Expected: { token, refreshToken, expiresAt, sessionId, user: { role: "SUPER_ADMIN" } }
```

### 3. Refresh Token Test
```bash
REFRESH="your_refresh_token_from_login"
curl -X POST https://wadjet-eye-ai.onrender.com/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH\"}" | jq
# Expected: { token: "NEW_TOKEN", refreshToken: "NEW_REFRESH_TOKEN", ... }
```

### 4. Vulnerability Sync
```bash
TOKEN="your_access_token"
# Trigger CISA KEV sync:
curl -X POST https://wadjet-eye-ai.onrender.com/api/vulnerabilities/sync \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source":"cisa_kev"}' | jq
# Expected: { message: "Sync started", source: "cisa_kev" }
```

### 5. Sysmon Test Upload
```bash
# Test with minimal JSON event:
curl -X POST https://wadjet-eye-ai.onrender.com/api/sysmon/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "test.json",
    "format": "json",
    "content": "[{\"EventID\":1,\"CommandLine\":\"powershell.exe -enc dGVzdA==\",\"Image\":\"C:\\\\Windows\\\\powershell.exe\"}]"
  }' | jq
# Expected: { session_id: "...", status: "processing" }
```

### 6. Report Generation
```bash
curl -X POST https://wadjet-eye-ai.onrender.com/api/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Test Executive Report","report_type":"executive_summary"}' | jq
# Expected: { id: "...", message: "Report generation started", status: "generating" }
```

### 7. Frontend Tests (Browser)
1. Visit https://wadjet-eye-ai.vercel.app
2. **Login** with `mahmoud.osman@wadjet.ai` → should authenticate via real backend
3. **Refresh page** → should stay logged in (session restore)
4. **Kill Chain** page → should show 14 ATT&CK tactics with coverage bars
5. **Exposure/CVEs** page → should list CVEs from NVD (or empty if not synced yet)
6. **Sysmon** page → should show analysis sessions and upload form
7. **Executive Dashboard** → should show Generate Report button
8. **Click any alert/IOC/CVE** → detail modal should open with full metadata

### 8. Verify No Mock Data
Open browser DevTools → Network tab → look for API calls to `/api/...`
- All calls should return real data (200 OK) or empty arrays
- No calls should return hardcoded mock data
- No "bypass-demo-token" should appear in request headers

---

*Enterprise v4.0 Implementation Guide — Wadjet-Eye AI*
