# 🚀 ThreatPilot AI — Production SaaS Upgrade Guide
## Complete Step-by-Step Implementation Manual
### Version 2.0.0 | From Static SPA → Production-Ready Platform

---

## 📋 TABLE OF CONTENTS

1. [Architecture Overview](#architecture)
2. [What Was Built](#what-was-built)
3. [Folder Structure](#folder-structure)
4. [Step 1 — Supabase Setup](#step-1--supabase-setup)
5. [Step 2 — Backend Deployment](#step-2--backend-deployment)
6. [Step 3 — Frontend Integration](#step-3--frontend-integration)
7. [Step 4 — API Key Configuration](#step-4--api-key-configuration)
8. [Step 5 — First Login](#step-5--first-login)
9. [API Reference](#api-reference)
10. [Security Checklist](#security-checklist)
11. [Scaling & Performance](#scaling--performance)
12. [Troubleshooting](#troubleshooting)

---

## 🏗️ ARCHITECTURE OVERVIEW {#architecture}

```
┌─────────────────────────────────────────────────────────────┐
│                     PRODUCTION ARCHITECTURE                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐    HTTPS     ┌──────────────────────────┐  │
│  │   Browser    │◄────────────►│   Vercel (Frontend)      │  │
│  │  (SPA + WS)  │              │   Static HTML/JS/CSS      │  │
│  └──────┬───────┘              └──────────────────────────┘  │
│         │ REST API + WebSocket                                 │
│         ▼                                                      │
│  ┌──────────────────────────────────────────────────────┐     │
│  │              Render / Railway (Backend)               │     │
│  │              Node.js + Express v4                     │     │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │     │
│  │  │  /alerts │ │  /cases  │ │  /iocs   │ │/intel  │  │     │
│  │  │  CRUD    │ │  CRUD    │ │  +enrich │ │ Proxy  │  │     │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────┘  │     │
│  │  ┌──────────────────────────────────────────────┐    │     │
│  │  │  Socket.IO — Real-time Events                │    │     │
│  │  └──────────────────────────────────────────────┘    │     │
│  └──────────────────────┬───────────────────────────────┘     │
│                         │ Supabase SDK                         │
│                         ▼                                      │
│  ┌──────────────────────────────────────────────────────┐     │
│  │              Supabase (Database + Auth)               │     │
│  │  PostgreSQL + Auth + RLS + Realtime                   │     │
│  │  Tables: tenants, users, alerts, cases, iocs,         │     │
│  │          audit_logs, playbooks, cache                 │     │
│  └──────────────────────────────────────────────────────┘     │
│                         │                                      │
│                         ▼                                      │
│  ┌──────────────────────────────────────────────────────┐     │
│  │           External Threat Intel APIs                  │     │
│  │  VirusTotal │ AbuseIPDB │ Shodan │ AlienVault OTX     │     │
│  │  (All keys stored server-side — never in frontend)    │     │
│  └──────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

**Key Security Properties:**
- 🔐 API keys NEVER reach the browser
- 🏢 Multi-tenant isolation via RLS at database level
- 🔑 JWT tokens via Supabase Auth (industry standard)
- 📋 Every action audited in `audit_logs` table
- 🚦 Rate limiting on all endpoints

---

## 📦 WHAT WAS BUILT {#what-was-built}

| File | Purpose |
|------|---------|
| `backend/server.js` | Main Express server, CORS, helmet, rate limiting |
| `backend/config/supabase.js` | Supabase client singleton |
| `backend/middleware/auth.js` | JWT verification, RBAC enforcement, tenant isolation |
| `backend/middleware/audit.js` | Automatic audit logging for all mutations |
| `backend/middleware/errorHandler.js` | Global error handler |
| `backend/routes/auth.js` | Login, logout, refresh, user profile |
| `backend/routes/alerts.js` | Full alerts CRUD + assign/escalate + realtime |
| `backend/routes/cases.js` | Case management CRUD + notes + IOC linking |
| `backend/routes/iocs.js` | IOC database + bulk import + enrichment trigger |
| `backend/routes/users.js` | User management CRUD + password reset |
| `backend/routes/intel.js` | VirusTotal, AbuseIPDB, Shodan, OTX proxies + cache |
| `backend/routes/auditLogs.js` | Audit log viewing and CSV export |
| `backend/routes/tenants.js` | Multi-tenant management |
| `backend/routes/dashboard.js` | KPI aggregations for command center |
| `backend/routes/playbooks.js` | Playbook CRUD |
| `backend/services/enrichment.js` | Background IOC enrichment service |
| `backend/realtime/websockets.js` | Socket.IO server, live detections, tenant rooms |
| `backend/database/schema.sql` | Complete PostgreSQL schema with RLS policies |
| `backend/.env.example` | Environment variable template |
| `js/api-client.js` | Frontend API client (replaces static ARGUS_DATA) |

---

## 📁 FOLDER STRUCTURE {#folder-structure}

```
threatpilot/
├── backend/                    ← NEW: Node.js API server
│   ├── server.js               ← Entry point
│   ├── package.json
│   ├── .env.example            ← Template (copy to .env)
│   ├── .env                    ← YOUR secrets (never commit!)
│   ├── config/
│   │   └── supabase.js         ← DB client
│   ├── middleware/
│   │   ├── auth.js             ← JWT + RBAC
│   │   ├── audit.js            ← Audit logging
│   │   └── errorHandler.js
│   ├── routes/
│   │   ├── auth.js
│   │   ├── alerts.js
│   │   ├── cases.js
│   │   ├── iocs.js
│   │   ├── users.js
│   │   ├── intel.js            ← Threat intel proxy
│   │   ├── auditLogs.js
│   │   ├── tenants.js
│   │   ├── dashboard.js
│   │   └── playbooks.js
│   ├── services/
│   │   └── enrichment.js       ← IOC enrichment service
│   ├── realtime/
│   │   └── websockets.js       ← Socket.IO server
│   └── database/
│       └── schema.sql          ← Run this in Supabase!
│
├── css/                        ← Existing frontend styles
├── js/
│   ├── api-client.js           ← NEW: Frontend → Backend bridge
│   ├── data.js                 ← Existing static data (fallback)
│   ├── main.js
│   └── ...
└── index.html
```

---

## STEP 1 — SUPABASE SETUP {#step-1--supabase-setup}

### 1.1 Create Supabase Project

```
1. Go to https://supabase.com
2. Click "New Project"
3. Name it: threatpilot-production
4. Choose region closest to your users (e.g., EU West for Europe)
5. Set a strong database password (save it!)
6. Wait ~2 minutes for setup
```

### 1.2 Run the Database Schema

```
1. In Supabase → SQL Editor
2. Click "+ New Query"
3. Paste the ENTIRE contents of: backend/database/schema.sql
4. Click "Run" (green button)
5. You should see: "Success. No rows returned"
```

### 1.3 Create Your First Admin User

```
1. In Supabase → Authentication → Users
2. Click "Add User"
3. Enter: mahmoud@mssp.com
4. Enter a strong password
5. Click "Create User"
6. Copy the UUID that appears (you need it in the next step)
```

### 1.4 Seed the Admin Profile

In Supabase SQL Editor, run:
```sql
-- Replace 'YOUR-UUID-HERE' with the UUID from step 1.3
INSERT INTO public.users (auth_id, tenant_id, name, email, role, avatar, permissions, status)
VALUES (
  'YOUR-UUID-HERE',
  '00000000-0000-0000-0000-000000000001',  -- MSSP tenant
  'Mahmoud Osman',
  'mahmoud@mssp.com',
  'SUPER_ADMIN',
  'MO',
  ARRAY['all'],
  'active'
);
```

### 1.5 Get Your Supabase Keys

```
Supabase Dashboard → Settings → API

You need:
  Project URL:     https://xxxxxxxxxxxx.supabase.co
  anon/public key: eyJhbGciOiJIUzI1NiIsInR5cCI6...  (safe for frontend)
  service_role key: eyJhbGciOiJIUzI1NiIsInR5cCI6...  ⚠️ BACKEND ONLY!
```

> ⚠️ **CRITICAL**: The `service_role` key bypasses all RLS.
> NEVER put it in your frontend code. Backend only!

---

## STEP 2 — BACKEND DEPLOYMENT {#step-2--backend-deployment}

### Option A: Deploy to Render (Recommended — Free tier available)

```bash
# 1. Push your backend to GitHub
cd backend
git init
git add .
git commit -m "ThreatPilot backend v2"
git remote add origin https://github.com/YOUR-USERNAME/threatpilot-backend
git push -u origin main

# 2. Go to https://render.com
# 3. New → Web Service
# 4. Connect your GitHub repo
# 5. Settings:
#    Name:        threatpilot-api
#    Environment: Node
#    Build Cmd:   npm install
#    Start Cmd:   node server.js
#    Instance:    Free (or Starter for production)

# 6. Add Environment Variables (Render dashboard → Environment):
#    NODE_ENV          = production
#    SUPABASE_URL      = https://xxx.supabase.co
#    SUPABASE_ANON_KEY = eyJ...
#    SUPABASE_SERVICE_KEY = eyJ...  (keep secret!)
#    VIRUSTOTAL_API_KEY   = your-key
#    ABUSEIPDB_API_KEY    = your-key
#    SHODAN_API_KEY       = your-key
#    OTX_API_KEY          = your-key
#    FRONTEND_URL         = https://your-vercel-app.vercel.app
#    ALLOWED_ORIGINS      = https://your-vercel-app.vercel.app

# 7. Click "Create Web Service"
# 8. Wait for deploy (~3 min)
# 9. Your API URL: https://threatpilot-api.onrender.com
```

### Option B: Deploy to Railway

```bash
# 1. Go to https://railway.app
# 2. New Project → Deploy from GitHub Repo
# 3. Select your backend repo
# 4. Add the same env variables as above
# 5. Railway auto-detects Node.js and deploys
# 6. Get URL from: Settings → Domains
```

### Option C: Run Locally (Development)

```bash
cd backend
cp .env.example .env
# Edit .env with your real values

npm install
npm run dev   # Uses nodemon for hot reload

# Server runs at: http://localhost:4000
# Test: curl http://localhost:4000/health
```

---

## STEP 3 — FRONTEND INTEGRATION {#step-3--frontend-integration}

### 3.1 Add the API Client to index.html

Add this line to `index.html` **before** `js/main.js`:

```html
<!-- Add your backend URL -->
<script>
  window.THREATPILOT_API_URL = 'https://YOUR-RENDER-URL.onrender.com';
  window.THREATPILOT_WS_URL  = 'https://YOUR-RENDER-URL.onrender.com';
</script>

<!-- Add Socket.IO client -->
<script src="https://cdn.jsdelivr.net/npm/socket.io-client@4/dist/socket.io.min.js"></script>

<!-- Add our API client -->
<script src="js/api-client.js"></script>
```

### 3.2 Switch Login to Backend Mode

In `index.html`, update the login button:

```html
<!-- BEFORE (static): -->
<button class="login-btn" onclick="doLogin()">Sign In Securely</button>

<!-- AFTER (real backend): -->
<button class="login-btn" onclick="doLoginBackend()">Sign In Securely</button>
```

### 3.3 Connect Real-time on App Init

In `js/main.js`, update `initApp()`:

```javascript
function initApp() {
  // ... existing code ...

  // Add these lines:
  if (window.WS) {
    WS.connect();
    WS.subscribeAlerts();
    initRealtime(); // from api-client.js
  }

  // Load real dashboard data
  if (window.loadDashboardData) {
    loadDashboardData();
  }
}
```

### 3.4 Replace Static Calls (Gradual Migration)

The platform will continue working with static data while you migrate.
Replace individual calls like this:

```javascript
// BEFORE (static):
const findings = ARGUS_DATA.findings;

// AFTER (real API):
const findings = await loadAlerts({ severity: 'CRITICAL' });
```

---

## STEP 4 — API KEY CONFIGURATION {#step-4--api-key-configuration}

| Service | Free Tier | How to Get |
|---------|-----------|------------|
| **VirusTotal** | 4 req/min | https://virustotal.com/gui/my-apikey |
| **AbuseIPDB** | 1000 checks/day | https://abuseipdb.com/account/api |
| **Shodan** | 100 results | https://account.shodan.io |
| **AlienVault OTX** | Unlimited pulses | https://otx.alienvault.com/api |

**If you don't have keys yet:**
The backend will return `503 Not Configured` for that source
and the platform will still work with the available sources.

---

## STEP 5 — FIRST LOGIN {#step-5--first-login}

```
URL:      https://your-vercel-app.vercel.app
Email:    mahmoud@mssp.com
Password: (the one you set in Supabase Auth)
Tenant:   MSSP Global Operations
```

On first login you will see real data loading from your Supabase database.
The platform gracefully falls back to static demo data if the API is unreachable.

---

## 📡 API REFERENCE {#api-reference}

### Authentication
```
POST /api/auth/login           { email, password, tenant_id }
POST /api/auth/logout
POST /api/auth/refresh         { refresh_token }
GET  /api/auth/me
```

### Alerts
```
GET    /api/alerts             ?severity=CRITICAL&status=open&page=1&limit=25
GET    /api/alerts/stats
GET    /api/alerts/:id
POST   /api/alerts             { title, severity, type, ioc_value, ... }
PATCH  /api/alerts/:id         { status, assigned_to, notes }
DELETE /api/alerts/:id         (ADMIN only)
POST   /api/alerts/:id/assign  { assigned_to: "user-uuid" }
POST   /api/alerts/:id/escalate
```

### Cases
```
GET    /api/cases              ?status=open&assigned_to=uuid
GET    /api/cases/:id          (includes notes, timeline, IOCs)
POST   /api/cases              { title, severity, description, sla_hours }
PATCH  /api/cases/:id
DELETE /api/cases/:id          (ADMIN only)
POST   /api/cases/:id/notes    { content }
POST   /api/cases/:id/iocs     { ioc_id }
```

### IOCs
```
GET    /api/iocs               ?type=ip&risk_min=70&search=185.220
GET    /api/iocs/:id
POST   /api/iocs               { value, type, source }
POST   /api/iocs/bulk          { iocs: [{value,type},...] }
GET    /api/iocs/:id/enrich    (calls VT + AbuseIPDB + Shodan + OTX)
POST   /api/iocs/pivot         { field: "asn", value: "AS12345" }
PATCH  /api/iocs/:id
DELETE /api/iocs/:id
```

### Threat Intelligence
```
POST /api/intel/virustotal     { ioc, type }
POST /api/intel/abuseipdb      { ip }
POST /api/intel/shodan         { ip }
POST /api/intel/otx            { ioc, type }
POST /api/intel/enrich         { ioc, type }   ← unified
GET  /api/intel/feeds                           ← feed status
```

### Users (ADMIN+)
```
GET    /api/users
GET    /api/users/:id
POST   /api/users              { name, email, password, role }
PATCH  /api/users/:id
DELETE /api/users/:id          (SUPER_ADMIN)
POST   /api/users/:id/reset-password
PATCH  /api/users/:id/status   { status: "active"|"suspended" }
```

### Audit Logs (ADMIN+)
```
GET /api/audit                 ?user_id=uuid&action=LOGIN&from=2024-01-01
GET /api/audit/user/:userId
GET /api/audit/export          (CSV download)
```

### Dashboard
```
GET /api/dashboard             (KPIs, alert trend, severity breakdown)
```

---

## 🔐 SECURITY CHECKLIST {#security-checklist}

### ✅ Already Implemented
- [x] API keys stored in server environment (never frontend)
- [x] JWT authentication on all protected routes
- [x] RBAC enforcement (server-side, not client-side)
- [x] Tenant isolation (every query scoped to tenant_id)
- [x] Row Level Security in PostgreSQL
- [x] Audit logging for all mutations
- [x] Rate limiting (500/15min global, 10/15min auth, 30/min intel)
- [x] CORS restricted to allowed origins
- [x] Helmet.js security headers (CSP, HSTS, X-Frame-Options)
- [x] Input validation on all endpoints
- [x] Sensitive fields redacted in audit logs (passwords, tokens)
- [x] Request body size limits (5MB max)
- [x] WebSocket authentication (JWT required to connect)
- [x] HTTPS enforced via Render/Vercel (TLS 1.3)

### 📋 Production Hardening (Do Before Go-Live)
- [ ] Change all demo passwords to strong unique passwords
- [ ] Enable Supabase Auth email verification
- [ ] Set up Supabase Auth MFA (TOTP)
- [ ] Configure custom domain with your SSL cert
- [ ] Set up database backups (Supabase → Settings → Backups)
- [ ] Enable Supabase Vault for API key rotation
- [ ] Add monitoring (Render metrics or Datadog)
- [ ] Set up error alerting (Sentry)
- [ ] Review and tighten CSP headers for your domain
- [ ] Schedule audit_logs cleanup (keep 90 days, archive rest)
- [ ] Add API key rotation schedule (every 90 days)

---

## ⚡ SCALING & PERFORMANCE {#scaling--performance}

### Database Indexes
All critical query paths are indexed:
- `alerts(tenant_id, severity, status, created_at)`
- `iocs(tenant_id, type, risk_score, value gin_trgm)`
- Full-text search on alerts via `to_tsvector`

### Caching Strategy
- IOC enrichment results cached 60 minutes in `ioc_enrichment_cache`
- Dashboard KPIs: cache at frontend (30-second TTL) for high traffic
- Rate limits protect external API quotas

### When to Upgrade
| Users | Recommended Setup |
|-------|------------------|
| 1–50 | Render Free + Supabase Free |
| 50–500 | Render Starter ($7/mo) + Supabase Pro ($25/mo) |
| 500+ | Render Standard + Supabase Pro + Redis caching |
| Enterprise | Dedicated cluster + CloudFront CDN + WAF |

---

## 🔧 TROUBLESHOOTING {#troubleshooting}

### "Cannot reach backend"
```bash
# Check backend is running:
curl https://your-api.onrender.com/health

# Expected response:
{"status":"OK","version":"2.0.0","environment":"production"}
```

### "Invalid or expired token"
- Your JWT may be expired (default 1 hour)
- The frontend `api-client.js` auto-refreshes — check for network errors
- Check `SUPABASE_URL` and `SUPABASE_SERVICE_KEY` in your .env

### "CORS blocked"
```
Add your frontend URL to ALLOWED_ORIGINS in backend .env:
ALLOWED_ORIGINS=https://your-vercel-app.vercel.app
```

### "User profile not found"
You created the auth user in Supabase but forgot to insert into `users` table.
Run the seed SQL from Step 1.4.

### VirusTotal / AbuseIPDB returns 503
The API key for that service isn't set in `.env`.
Platform will still work — just that source won't return data.

---

## 📊 DATA MIGRATION FROM STATIC

If you want to seed your real database with the existing mock data:

```javascript
// Run this in browser console after logging in with real credentials
async function migrateStaticData() {
  // Migrate findings as alerts
  for (const f of ARGUS_DATA.findings) {
    await API.alerts.create({
      title:           f.value || f.type,
      description:     f.description,
      severity:        f.severity,
      type:            f.type,
      ioc_value:       f.value,
      source:          f.source,
      mitre_technique: f.mitre
    });
  }
  console.log('Migration complete!');
}
migrateStaticData();
```

---

*ThreatPilot AI v2.0.0 — Production SaaS Architecture*
*Designed for security analysts, MSSPs, and threat intelligence teams*
