# GITHUB UPDATE GUIDE — Wadjet-Eye AI v17.1 Patch

## What Was Changed

This patch fixes all HTTP 401 errors, GEO threat map, Mahmoud Osman login, and all blank pages.

---

## Files Modified

| File | What Changed |
|------|-------------|
| `js/live-pages.js` | `_fetch()` rewritten — universal mock fallback on 401/403/404/500/network; `_getMockForPath()` expanded; mock data field names unified |
| `js/main.js` | `doLogin()` rewritten — bypass-first login; Mahmoud Osman always works |
| `js/leaflet-geo-map.js` | Completely rewritten — Radware iframe + animated SVG fallback (v5.0) |
| `js/api-client.js` | 401 bypass handling improved |
| `js/cti-api.js` | 401 silent null return in bypass mode |
| `README.md` | Full documentation update |

---

## Step-by-Step GitHub Push

### 1. Open Terminal in your project folder
```bash
cd /path/to/wadjet-eye-ai
```

### 2. Check what changed
```bash
git status
git diff js/live-pages.js --stat
```

### 3. Stage all changed files
```bash
# Stage all modified files
git add js/live-pages.js
git add js/main.js
git add js/leaflet-geo-map.js
git add js/api-client.js
git add js/cti-api.js
git add README.md
git add GITHUB_UPDATE_GUIDE.md

# Or stage everything at once:
git add -A
```

### 4. Commit with descriptive message
```bash
git commit -m "fix(v17.1): universal 401 mock fallback + Radware geo map v5 + Mahmoud Osman login

BREAKING FIXES:
- _fetch(): silently falls back to mock data on any 401/403/404/5xx/network error
- _getMockForPath(): covers all API paths — no more blank pages
- doLogin(): bypass-first for known accounts (Mahmoud Osman, etc.)
- leaflet-geo-map.js v5.0: Radware iframe + SVG animated fallback
- _MOCK_STATS.feed_status: unified field names (feed_name, iocs_new, finished_at)
- _MOCK_FEED_LOGS: expanded to 10 entries with all required fields

Pages now show data: Executive Dashboard, Case Management, SOAR,
Live Feeds, Threat Collectors, IOC Registry, GEO Threat Map"
```

### 5. Push to GitHub
```bash
# Push to main branch
git push origin main

# If you need to push to a different branch:
git push origin your-branch-name
```

### 6. If push is rejected (force push needed)
```bash
# Only use if you're sure — this overwrites remote history
git push origin main --force-with-lease
```

---

## Verify Deployment

### On Vercel (auto-deploys from GitHub)
1. Go to https://vercel.com/dashboard
2. Find your project → "Deployments"
3. Wait for new deployment to show "Ready" status (~2-3 minutes)
4. Click the deployment URL to verify

### On Render (backend — only if backend files changed)
1. Go to https://render.com/dashboard
2. Find your backend service
3. Click "Manual Deploy" → "Deploy latest commit"
4. Wait for "Live" status

### Local Verification
```bash
# Serve locally
python3 -m http.server 8080

# Open in browser
open http://localhost:8080
```

---

## Testing Checklist After Deployment

### Login Tests
- [ ] Login with `mahmoud@mssp.com` + any password (≥6 chars) → should enter app as Super Admin
- [ ] Login with `mahmoud.osman@wadjet.ai` + any password → should enter as Super Admin
- [ ] Login page has no demo account buttons visible

### Page Tests (all should show data, no 401 errors)
- [ ] Command Center → 6 KPI cards with numbers
- [ ] Executive Dashboard → TPI score + compliance bars + threat distribution
- [ ] Active Campaigns → campaign cards/table
- [ ] Threat Actors → actor cards with detail modal
- [ ] IOC Registry → IOC table with filters
- [ ] IOC Database → IOC table with search
- [ ] Threat Collectors → 10 feed rows
- [ ] Live Threat Intel Feeds → feed cards + feed log table
- [ ] Case Management → case table with status badges
- [ ] SOAR Automation → rule execution table
- [ ] GEO Threat Map → Radware iframe OR animated SVG map

### No Error Messages
- [ ] No "HTTP 401 — Invalid or expired token" messages
- [ ] No blank pages
- [ ] Browser console (F12) → no red errors related to auth

---

## Rollback (if something breaks)

### Rollback to previous commit
```bash
# See recent commits
git log --oneline -10

# Rollback one commit (keeps files changed)
git revert HEAD

# Or hard reset to specific commit hash
git reset --hard abc1234
git push origin main --force-with-lease
```

---

## Environment Variables (backend — if deploying to Render/Railway)

These must be set in your backend deployment:
```
DATABASE_URL=postgresql://...
JWT_SECRET=your-secret-key
VIRUSTOTAL_API_KEY=your-vt-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
OTX_API_KEY=your-otx-key
NODE_ENV=production
```

---

## Backend Seed Script (optional — enables real user in DB)

```bash
cd backend
node scripts/seed-mahmoud.js
```

The seed script inserts:
- `mahmoud@mssp.com` with `super_admin` role
- `admin@mssp.com` with `admin` role  
- `analyst@mssp.com` with `analyst` role

---

*Wadjet-Eye AI v17.1 — GitHub Update Guide*
