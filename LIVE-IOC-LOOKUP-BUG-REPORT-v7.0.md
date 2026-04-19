# Live IOC Lookup — Bug Report & Fix Documentation v7.0
**Date:** 2026-04-13  
**Branch:** `genspark_ai_developer_v36`  
**Scope:** `js/live-ioc-lookup-v3.js`, `api/proxy/*.js`, `proxy-server.js`, `vercel.json`, `api/_proxy-utils.js`

---

## Executive Summary

The Live IOC Lookup module failed across **all five intelligence sources** (VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, URLhaus) because:

1. **API keys stored in browser localStorage were never forwarded to the server-side proxies** — the proxies looked only at server environment variables.
2. **Vercel environment variables (VT_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY, OTX_API_KEY) were not configured** on the deployment.
3. **URLhaus proxy was newly added** but not yet deployed, causing 404 errors.
4. **The `_safeProxyFetch` helper** didn't handle network failures gracefully.

---

## Root Cause Analysis

### Architecture Overview

```
Browser (Vercel static site)
  │
  ├─ /proxy/vt/*       → Vercel serverless function (api/proxy/vt.js)
  ├─ /proxy/abuseipdb/ → Vercel serverless function (api/proxy/abuseipdb.js)
  ├─ /proxy/shodan/    → Vercel serverless function (api/proxy/shodan.js)
  ├─ /proxy/otx/       → Vercel serverless function (api/proxy/otx.js)
  ├─ /proxy/urlhaus/   → Vercel serverless function (api/proxy/urlhaus.js)
  │
  └─ Fallback: POST /api/intel/* → Render Express backend
```

### Bug Table

| # | Source | Symptom | Root Cause |
|---|--------|---------|------------|
| BUG-1 | VirusTotal | HTTP 503 from backend | Proxy env var missing; backend fallback requires JWT + server VT key |
| BUG-2 | AbuseIPDB | HTTP 404 from proxy | Proxy deployed but env var missing → returned `missing_api_key`; user's localStorage key was never sent |
| BUG-3 | Shodan | HTTP 404 from proxy | Same as BUG-2 |
| BUG-4 | AlienVault OTX | HTTP 404 from proxy | Same as BUG-2 (OTX is public but env var check blocked user key usage) |
| BUG-5 | URLhaus | HTTP 404 from proxy | New `urlhaus.js` function was added to the repo but Vercel hadn't redeployed |
| BUG-6 | All sources | User keys ignored | `X-Client-*` headers from frontend were received by proxy but NOT read |

### Critical Missing Link: Client Key Headers

The frontend code correctly stored user-provided API keys in localStorage and sent them as `X-Client-*` request headers:
```javascript
// Frontend (js/live-ioc-lookup-v3.js)
if (vtKey) headers['X-Client-VT-Key'] = vtKey;
```

But the server-side proxy functions (`api/proxy/vt.js`, etc.) only checked `process.env.VT_API_KEY` and **completely ignored** the `X-Client-VT-Key` header. This meant that even if users had configured their API keys in the browser, the proxies would still return `missing_api_key`.

---

## Fixes Applied

### 1. All Vercel Proxy Functions — Accept Client Keys as Fallback

**Files:** `api/proxy/vt.js`, `api/proxy/abuseipdb.js`, `api/proxy/shodan.js`, `api/proxy/otx.js`

**Before:**
```javascript
// Only checked server env var — ignored client-provided key
const vtKey = process.env.VT_API_KEY;
if (!vtKey) {
  sendJSON(res, 200, { status: 'missing_api_key', ... });
  return;
}
```

**After:**
```javascript
// Key resolution: server env var → client header (browser localStorage key)
const vtKey = process.env.VT_API_KEY || req.headers['x-client-vt-key'] || '';
if (!vtKey) {
  sendJSON(res, 200, { status: 'missing_api_key', ... });
  return;
}
```

**Key mapping:**
| Service | Env Var | Client Header |
|---------|---------|---------------|
| VirusTotal | `VT_API_KEY` | `X-Client-VT-Key` |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | `X-Client-Abuse-Key` |
| Shodan | `SHODAN_API_KEY` | `X-Client-Shodan-Key` |
| OTX | `OTX_API_KEY` (optional) | `X-Client-OTX-Key` |

### 2. URLhaus Proxy — Proper POST Body Handling

**File:** `api/proxy/urlhaus.js`

- Reads the form-encoded POST body before forwarding
- Preserves `Content-Type: application/x-www-form-urlencoded`
- Added to Vercel `functions` config with 30s max duration

### 3. CORS Headers Updated

**Files:** `api/_proxy-utils.js`, `vercel.json`, `proxy-server.js`

Added new client key headers to `Access-Control-Allow-Headers`:
```
X-Client-VT-Key, X-Client-Abuse-Key, X-Client-Shodan-Key, X-Client-OTX-Key
```

### 4. `proxy-server.js` — Local Dev Server

Updated all proxy route handlers to use the same `server env var → client header` fallback pattern.

### 5. `_safeProxyFetch` — Improved Error Handling

- Added `AbortSignal.timeout(20000)` for 20-second timeout
- Catches network errors and wraps them as `PROXY_UNAVAILABLE`
- Better error body extraction for diagnosis
- Properly distinguishes proxy-level errors from upstream API errors

---

## How It Works Now

### User Flow

1. User opens the app and clicks **"API Keys"** button
2. Enters their VirusTotal / AbuseIPDB / Shodan / OTX keys
3. Keys are saved to `localStorage` (never leaves the browser)
4. On lookup, the frontend sends keys as `X-Client-*` headers to `/proxy/*`
5. The Vercel proxy function reads `X-Client-*` header and uses it to authenticate with the external API
6. Results flow back through the proxy with CORS headers to the browser

### Fallback Chain

```
Layer 1: /proxy/{source} (Vercel serverless)
  ✓ Uses server env var OR client header key
  → If HTML response (route not found): try Layer 2
  → If missing_api_key: show "Add Key" prompt

Layer 2: POST /api/intel/{source} (Render Express backend)
  ✓ Requires JWT + server-side API key
  → If 401: show "not logged in" message
  → If 503: show "key not configured" message

Layer 3: Graceful degradation
  ✓ Show "API key needed" card with link to configure
```

### URLhaus (No Key Required)

URLhaus is a free public API. The proxy simply adds `Accept: application/json` and forwards the POST body to `https://urlhaus-api.abuse.ch/v1/`. No authentication needed.

---

## Verification Checklist

After deployment to Vercel:

- [ ] User opens API Keys modal, enters VT key
- [ ] Lookup for IP `185.220.101.45` → VT card shows malicious/total
- [ ] Lookup for IP `185.220.101.45` → AbuseIPDB card shows abuse score
- [ ] Lookup for IP `185.220.101.45` → Shodan card shows open ports
- [ ] Lookup for domain `malware-update.ru` → OTX card shows pulse count
- [ ] Lookup for domain `malware-update.ru` → URLhaus card shows malicious URLs
- [ ] Console shows **zero** CORS errors or JSON parse errors
- [ ] Without keys: cards show "API key not configured — Add key" prompt
- [ ] After adding key: lookup works immediately without page refresh

---

## Files Changed

| File | Change |
|------|--------|
| `api/proxy/vt.js` | Added `x-client-vt-key` header fallback for VT API key |
| `api/proxy/abuseipdb.js` | Added `x-client-abuse-key` header fallback |
| `api/proxy/shodan.js` | Added `x-client-shodan-key` header fallback |
| `api/proxy/otx.js` | Added `x-client-otx-key` header fallback |
| `api/proxy/urlhaus.js` | Rewrote to properly forward POST body with form encoding |
| `api/_proxy-utils.js` | Added new client key headers to CORS allow list |
| `vercel.json` | Added client key headers to CORS headers config |
| `proxy-server.js` | Updated all route handlers with client key fallback; updated CORS |
| `js/live-ioc-lookup-v3.js` | Improved `_safeProxyFetch` with timeout + network error handling |
| `LIVE-IOC-LOOKUP-BUG-REPORT-v7.0.md` | This document |
