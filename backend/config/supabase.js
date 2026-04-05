/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Supabase Client v5.4 (JWT Migration Fix)
 *  backend/config/supabase.js
 *
 *  v5.4 CHANGES — JWT Migration Fix:
 *  ──────────────────────────────────
 *  Supabase has migrated from a single "Legacy JWT Secret" (HS256
 *  symmetric key shared by all projects) to a new per-project
 *  "JWT Signing Keys" system.
 *
 *  WHAT THIS MEANS FOR YOUR APP:
 *  ─────────────────────────────
 *  1. Your old anon/service_role keys (eyJhbGci...) were JWTs signed
 *     with the legacy shared secret. They still WORK until you explicitly
 *     revoke them via Supabase Dashboard → Settings → API → JWT Settings.
 *
 *  2. The warning "Legacy JWT secret has been migrated to new JWT Signing
 *     Keys" is INFORMATIONAL — it does NOT break your existing keys yet.
 *
 *  3. The new "Publishable Key" (sb_publishable_...) replaces the anon key.
 *     The new "Secret Key" (sb_secret_...) replaces the service_role key.
 *     Both old and new key formats are supported by this file.
 *
 *  4. Your HTTP 401 errors (MISSING_TOKEN) are caused by the frontend
 *     NOT sending the Authorization: Bearer header, NOT by the key
 *     migration. See jwt-migration-guide.html for the full fix.
 *
 *  HOW TO MIGRATE (do this in Render Dashboard Environment vars):
 *  ──────────────────────────────────────────────────────────────
 *  SUPABASE_ANON_KEY    → sb_publishable_LwTPXF-cDzMcmc_V16N9lA_KvN-ElTZ
 *  SUPABASE_SERVICE_KEY → sb_secret_xDSevd4Gq3--9EPiWAcl0w_1M5S7M1_
 *  JWT_SECRET           → (keep current value unless Supabase shows new one)
 *
 *  KEY FORMAT DETECTION:
 *  ─────────────────────
 *  • Legacy:  starts with "eyJ" (base64-encoded JWT)
 *  • New:     starts with "sb_publishable_" or "sb_secret_"
 *  Both formats are fully supported below.
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const { createClient } = require('@supabase/supabase-js');

// ── Required env vars ──────────────────────────────────────────────
const SUPABASE_URL      = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

// Support both variable names for service key
const SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY
                 || process.env.SUPABASE_SECRET_KEY;

// ── Startup validation ────────────────────────────────────────────
if (!SUPABASE_URL) {
  console.error('[Supabase] ❌ MISSING: SUPABASE_URL is not set in environment');
  console.error('[Supabase]    Add it to backend/.env AND to your Render Dashboard → Environment');
  process.exit(1);
}

if (!SERVICE_KEY) {
  console.error('[Supabase] ❌ MISSING: SUPABASE_SERVICE_KEY is not set in environment');
  console.error('[Supabase]    Get the "Secret Key" (sb_secret_...) from:');
  console.error('[Supabase]    https://supabase.com/dashboard/project/_/settings/api');
  console.error('[Supabase]    Add it to backend/.env AND to Render Dashboard → Environment');
  process.exit(1);
}

// ── Key format detection ──────────────────────────────────────────
function detectKeyFormat(key, name) {
  if (!key) return;

  const isNewSecret      = key.startsWith('sb_secret_');
  const isNewPublishable = key.startsWith('sb_publishable_');
  const isLegacyJWT      = key.startsWith('eyJ');

  if (isNewSecret || isNewPublishable) {
    const keyType = isNewSecret ? 'sb_secret_*' : 'sb_publishable_*';
    console.log(`[Supabase] ✅ ${name}: Using new API key format (${keyType})`);
  } else if (isLegacyJWT) {
    console.log(`[Supabase] ℹ️  ${name}: Using legacy JWT key format (eyJ...)`);
    console.log(`[Supabase]    Migrate to new format: Supabase Dashboard → Settings → API → API Keys`);
  } else {
    console.warn(`[Supabase] ⚠️  ${name}: Unrecognized key format — check your environment variable`);
  }
}

detectKeyFormat(SERVICE_KEY,       'SUPABASE_SERVICE_KEY');
detectKeyFormat(SUPABASE_ANON_KEY, 'SUPABASE_ANON_KEY   ');

// ── Service-role / Secret client ──────────────────────────────────
// Used SERVER-SIDE ONLY.
// • Bypasses ALL Row Level Security (RLS) policies.
// • NEVER expose this key in frontend JavaScript code.
// • Works with both legacy eyJ... and new sb_secret_... keys.
const supabase = createClient(
  SUPABASE_URL,
  SERVICE_KEY,
  {
    auth: {
      autoRefreshToken:   false,
      persistSession:     false,
      detectSessionInUrl: false,
    },
    db: { schema: 'public' },
    global: {
      headers: {
        'x-application-name': 'wadjet-eye-ai-backend',
      },
    },
  }
);

// ── Anon / Publishable client ─────────────────────────────────────
// Used for RLS-respecting reads and for initializing user sessions.
// Safe to use with user JWTs — respects tenant row-level security.
// Falls back to service client if anon key is not set.
const supabaseAnon = SUPABASE_ANON_KEY
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        autoRefreshToken:   false,
        persistSession:     false,
        detectSessionInUrl: false,
      },
    })
  : supabase;  // fallback: use service client (note: bypasses RLS)

if (!SUPABASE_ANON_KEY) {
  console.warn('[Supabase] ⚠️  SUPABASE_ANON_KEY not set — falling back to service client for anon ops');
  console.warn('[Supabase]    Set SUPABASE_ANON_KEY to the publishable key (sb_publishable_...) for proper RLS');
}

// ── User-scoped client factory ────────────────────────────────────
// Creates a Supabase client that acts as a specific authenticated user.
// The user's JWT is forwarded as the Authorization header.
// This ensures RLS policies run correctly for that user's tenant.
//
// Usage:
//   const userClient = supabaseForUser(req.token);
//   const { data } = await userClient.from('iocs').select('*');
//
function supabaseForUser(accessToken) {
  if (!accessToken) return supabaseAnon;

  return createClient(
    SUPABASE_URL,
    // Use anon key for user-scoped client (enables RLS)
    SUPABASE_ANON_KEY || SERVICE_KEY,
    {
      global: {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
      auth: {
        autoRefreshToken:   false,
        persistSession:     false,
        detectSessionInUrl: false,
      },
    }
  );
}

// ── Startup connectivity test (non-blocking) ─────────────────────
async function checkSupabaseConnection() {
  try {
    const start = Date.now();
    const { error } = await supabase
      .from('users')
      .select('id')
      .limit(1);

    const ms = Date.now() - start;

    if (error) {
      const isKeyError = error.message?.includes('JWT')
                      || error.message?.includes('token')
                      || error.message?.includes('Invalid API key')
                      || error.message?.includes('apikey')
                      || error.code === 'PGRST301';

      if (isKeyError) {
        console.error('[Supabase] 🔑 API KEY ERROR — your service key may be invalid or revoked');
        console.error('[Supabase]    Fix steps:');
        console.error('[Supabase]    1. Go to: https://supabase.com/dashboard/project/miywxnplaltduuscjfmq/settings/api');
        console.error('[Supabase]    2. Copy the "Secret Key" (sb_secret_...) from API Keys section');
        console.error('[Supabase]    3. Update SUPABASE_SERVICE_KEY in Render Dashboard → Environment');
        console.error('[Supabase]    4. Trigger a manual redeploy on Render');
        console.error('[Supabase]    Error detail:', error.message);
      } else {
        // Could be RLS or missing table — not necessarily a key problem
        console.warn(`[Supabase] ⚠️  Connection test returned error (${ms}ms): ${error.message}`);
        console.warn('[Supabase]    If this is an RLS error, run: backend/database/rls-fix-v5.1.sql');
      }
    } else {
      console.log(`[Supabase] ✅ Connection OK (${ms}ms) — Project: miywxnplaltduuscjfmq`);
    }
  } catch (err) {
    console.error('[Supabase] ❌ Connection check threw an exception:', err.message);
    console.error('[Supabase]    Check SUPABASE_URL is correct and reachable');
  }
}

// Run the connectivity check after server setup (non-blocking)
setImmediate(checkSupabaseConnection);

// ── Exports ────────────────────────────────────────────────────────
module.exports = { supabase, supabaseAnon, supabaseForUser };
