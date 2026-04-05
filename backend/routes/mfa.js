/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — MFA Routes v6.0
 *  backend/routes/mfa.js
 *
 *  TOTP-based Multi-Factor Authentication
 *  Enforced at identity layer — not a UI toggle
 *
 *  Routes:
 *  POST /api/auth/mfa/enroll        — Begin TOTP enrollment (returns QR)
 *  POST /api/auth/mfa/verify-enroll — Complete enrollment with first TOTP
 *  POST /api/auth/mfa/challenge     — Submit TOTP code during login
 *  POST /api/auth/mfa/disable       — Disable MFA (requires current TOTP)
 *  GET  /api/auth/mfa/status        — Check enrollment state
 *
 *  Dependencies:
 *    npm install otplib qrcode
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const router     = require('express').Router();
const crypto     = require('crypto');
const { authenticator } = require('otplib');
const QRCode     = require('qrcode');
const { supabase } = require('../config/supabase');
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

// ── TOTP Configuration ────────────────────────────────────────────
authenticator.options = {
  window: 1,      // Allow 1 step before/after for clock skew
  step:   30,     // 30-second TOTP window (RFC 6238 standard)
};

// Encryption key for storing TOTP secrets at rest
const TOTP_KEY = process.env.TOTP_ENCRYPTION_KEY;
if (!TOTP_KEY || TOTP_KEY.length < 32) {
  console.warn('[MFA] ⚠️  TOTP_ENCRYPTION_KEY not set or too short.');
  console.warn('[MFA]    Generate with: openssl rand -hex 32');
  console.warn('[MFA]    Add to backend/.env and Render environment variables.');
}

// ── Encryption helpers (AES-256-GCM for TOTP secrets) ─────────────
function encryptSecret(plaintext) {
  if (!TOTP_KEY) return plaintext; // Fallback if key not configured
  const iv         = crypto.randomBytes(16);
  const key        = Buffer.from(TOTP_KEY, 'hex').slice(0, 32);
  const cipher     = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted  = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag    = cipher.getAuthTag();
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

function decryptSecret(ciphertext) {
  if (!TOTP_KEY || !ciphertext.includes(':')) return ciphertext; // Unencrypted fallback
  const [ivHex, authTagHex, encryptedHex] = ciphertext.split(':');
  const key       = Buffer.from(TOTP_KEY, 'hex').slice(0, 32);
  const iv        = Buffer.from(ivHex, 'hex');
  const authTag   = Buffer.from(authTagHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const decipher  = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// ── Verify a TOTP code against stored (encrypted) secret ──────────
function verifyTOTP(encryptedSecret, code) {
  try {
    const secret = decryptSecret(encryptedSecret);
    return authenticator.check(code, secret);
  } catch (err) {
    console.error('[MFA] TOTP verification error:', err.message);
    return false;
  }
}

// ══════════════════════════════════════════════════════════════════
// GET /api/auth/mfa/status
// Returns current MFA enrollment state for the authenticated user
// ══════════════════════════════════════════════════════════════════
router.get('/status', verifyToken, asyncHandler(async (req, res) => {
  const { data: user } = await supabase
    .from('users')
    .select('mfa_enabled, totp_enrolled_at, role')
    .eq('id', req.user.id)
    .single();

  const enforced = ['ADMIN', 'SUPER_ADMIN', 'super_admin', 'admin'].includes(req.user.role);

  res.json({
    mfa_enabled:       user?.mfa_enabled || false,
    totp_enrolled_at:  user?.totp_enrolled_at || null,
    mfa_enforced_by_role: enforced,
    message: enforced && !user?.mfa_enabled
      ? 'Your role requires MFA enrollment. Please enroll now.'
      : null,
  });
}));

// ══════════════════════════════════════════════════════════════════
// POST /api/auth/mfa/enroll
// Begin TOTP enrollment — returns secret + QR code URI
// Authenticated user only (existing session required)
// ══════════════════════════════════════════════════════════════════
router.post('/enroll', verifyToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const email  = req.user.email;

  // Check if already enrolled
  const { data: existing } = await supabase
    .from('users')
    .select('mfa_enabled, totp_secret')
    .eq('id', userId)
    .single();

  if (existing?.mfa_enabled) {
    return res.status(400).json({
      error: 'MFA is already enrolled. Disable it first before re-enrolling.',
      code:  'MFA_ALREADY_ENROLLED',
    });
  }

  // Generate new TOTP secret
  const secret = authenticator.generateSecret(32); // 32-char base32 secret

  // Store pending (unconfirmed) secret — not yet active
  const encryptedSecret = encryptSecret(secret);
  await supabase.from('users').update({
    totp_secret_pending: encryptedSecret,
  }).eq('id', userId);

  // Generate QR code URI for authenticator apps
  const appName = 'Wadjet-Eye AI';
  const totpUri = authenticator.keyuri(email, appName, secret);
  const qrDataUrl = await QRCode.toDataURL(totpUri);

  res.json({
    secret,           // User can manually enter this if QR scan fails
    qr_data_url: qrDataUrl,
    totp_uri:    totpUri,
    instructions: [
      '1. Open your authenticator app (Google Authenticator, Authy, or 1Password)',
      '2. Scan the QR code or manually enter the secret key',
      `3. Enter the 6-digit code from the app to confirm enrollment`,
    ],
  });
}));

// ══════════════════════════════════════════════════════════════════
// POST /api/auth/mfa/verify-enroll
// Complete enrollment by verifying first TOTP code
// Body: { totp_code: "123456" }
// ══════════════════════════════════════════════════════════════════
router.post('/verify-enroll', verifyToken, asyncHandler(async (req, res) => {
  const { totp_code } = req.body;

  if (!totp_code || !/^\d{6}$/.test(totp_code)) {
    return res.status(400).json({ error: 'totp_code must be a 6-digit number', code: 'INVALID_CODE_FORMAT' });
  }

  const { data: user } = await supabase
    .from('users')
    .select('totp_secret_pending, mfa_enabled')
    .eq('id', req.user.id)
    .single();

  if (!user?.totp_secret_pending) {
    return res.status(400).json({
      error: 'No pending MFA enrollment found. Start with POST /api/auth/mfa/enroll',
      code:  'NO_PENDING_ENROLLMENT',
    });
  }

  const isValid = verifyTOTP(user.totp_secret_pending, totp_code);
  if (!isValid) {
    return res.status(401).json({
      error: 'Invalid TOTP code. Check your authenticator app and try again.',
      code:  'MFA_VERIFICATION_FAILED',
    });
  }

  // Activate MFA — move pending secret to active
  await supabase.from('users').update({
    mfa_enabled:          true,
    totp_secret:          user.totp_secret_pending,
    totp_secret_pending:  null,
    totp_enrolled_at:     new Date().toISOString(),
  }).eq('id', req.user.id);

  // Audit log
  await supabase.from('login_activity').insert({
    user_id:    req.user.id,
    tenant_id:  req.user.tenant_id,
    email:      req.user.email,
    action:     'MFA_ENROLLED',
    ip_address: req.ip,
    success:    true,
  });

  res.json({
    message: 'MFA enrolled successfully. TOTP will be required on next login.',
    mfa_enabled: true,
    enrolled_at: new Date().toISOString(),
  });
}));

// ══════════════════════════════════════════════════════════════════
// POST /api/auth/mfa/challenge
// Complete login MFA step (called after password auth returns mfa_required:true)
// Body: { mfa_session_token: "...", totp_code: "123456" }
// ══════════════════════════════════════════════════════════════════
router.post('/challenge', asyncHandler(async (req, res) => {
  const { mfa_session_token, totp_code } = req.body;

  if (!mfa_session_token || !totp_code) {
    return res.status(400).json({
      error: 'mfa_session_token and totp_code are required',
      code: 'MISSING_PARAMS',
    });
  }

  if (!/^\d{6}$/.test(totp_code)) {
    return res.status(400).json({ error: 'totp_code must be 6 digits', code: 'INVALID_CODE_FORMAT' });
  }

  // Validate the pre-auth MFA session token
  const tokenHash = crypto.createHash('sha256').update(mfa_session_token).digest('hex');
  const { data: challenge, error: chalErr } = await supabase
    .from('mfa_challenges')
    .select('*')
    .eq('pre_auth_token', tokenHash)
    .eq('used', false)
    .gt('expires_at', new Date().toISOString())
    .single();

  if (chalErr || !challenge) {
    return res.status(401).json({
      error: 'Invalid or expired MFA session. Please log in again.',
      code:  'MFA_SESSION_EXPIRED',
    });
  }

  // Get user's TOTP secret
  const { data: user } = await supabase
    .from('users')
    .select('id, name, email, role, tenant_id, totp_secret, status, permissions, avatar, mfa_enabled')
    .eq('id', challenge.user_id)
    .single();

  if (!user?.totp_secret) {
    return res.status(401).json({
      error: 'MFA not enrolled. Contact your administrator.',
      code:  'MFA_NOT_ENROLLED',
    });
  }

  // Verify TOTP code
  const isValid = verifyTOTP(user.totp_secret, totp_code);

  // Mark challenge as used (prevent replay)
  await supabase.from('mfa_challenges')
    .update({ used: true, used_at: new Date().toISOString() })
    .eq('id', challenge.id);

  if (!isValid) {
    await supabase.from('login_activity').insert({
      user_id: user.id, email: user.email,
      action: 'MFA_FAILED', ip_address: req.ip, success: false,
    });
    return res.status(401).json({
      error: 'Invalid MFA code. Try again.',
      code:  'MFA_INVALID',
    });
  }

  // MFA verified — issue full session (httpOnly cookies)
  const { data: supaSession } = await supabase.auth.admin.getUserById(challenge.user_id);
  const accessToken = supaSession?.user ? await getAccessTokenForUser(user) : null;

  // Set httpOnly session cookies
  const isProd = process.env.NODE_ENV === 'production';
  const cookieBase = { httpOnly: true, secure: isProd, sameSite: 'Strict' };

  if (accessToken) {
    res.cookie('waj_session', accessToken, {
      ...cookieBase,
      path: '/api',
      maxAge: parseInt(process.env.ACCESS_TOKEN_TTL || '900') * 1000,
    });
  }

  // Log successful MFA
  await supabase.from('login_activity').insert({
    user_id: user.id, tenant_id: user.tenant_id,
    email: user.email, action: 'MFA_SUCCESS',
    ip_address: req.ip, success: true,
  });

  res.json({
    user: {
      id:          user.id,
      name:        user.name,
      email:       user.email,
      role:        user.role,
      tenant_id:   user.tenant_id,
      avatar:      user.avatar,
      permissions: user.permissions,
      mfa_enabled: true,
    },
  });
}));

// ══════════════════════════════════════════════════════════════════
// POST /api/auth/mfa/disable
// Disable MFA — requires valid current TOTP code
// Body: { totp_code: "123456" }
// SUPER_ADMIN also requires admin approval (logged)
// ══════════════════════════════════════════════════════════════════
router.post('/disable', verifyToken, asyncHandler(async (req, res) => {
  const { totp_code } = req.body;

  if (!totp_code) {
    return res.status(400).json({ error: 'totp_code required to disable MFA', code: 'MISSING_CODE' });
  }

  const { data: user } = await supabase
    .from('users')
    .select('mfa_enabled, totp_secret, role')
    .eq('id', req.user.id)
    .single();

  if (!user?.mfa_enabled) {
    return res.status(400).json({ error: 'MFA is not enabled for this account', code: 'MFA_NOT_ENABLED' });
  }

  // Verify current TOTP before allowing disable
  const isValid = verifyTOTP(user.totp_secret, totp_code);
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid TOTP code', code: 'MFA_INVALID' });
  }

  // Super admins cannot self-disable without audit trail
  if (['SUPER_ADMIN', 'super_admin'].includes(user.role)) {
    await supabase.from('login_activity').insert({
      user_id:    req.user.id,
      email:      req.user.email,
      action:     'MFA_DISABLED_SUPER_ADMIN',
      ip_address: req.ip,
      success:    true,
      failure_reason: 'Admin manually disabled MFA — review required',
    });
  }

  await supabase.from('users').update({
    mfa_enabled:     false,
    totp_secret:     null,
    totp_enrolled_at: null,
  }).eq('id', req.user.id);

  res.json({ message: 'MFA disabled. You will no longer be prompted for TOTP on login.' });
}));

// ── Helper: get access token for user (used after MFA challenge) ──
async function getAccessTokenForUser(user) {
  try {
    const jwt = require('jsonwebtoken');
    const secret = process.env.JWT_SECRET;
    if (!secret) return null;
    return jwt.sign(
      { sub: user.id, email: user.email, role: user.role, tenant_id: user.tenant_id,
        iss: 'supabase', aud: 'authenticated' },
      secret,
      { expiresIn: parseInt(process.env.ACCESS_TOKEN_TTL || '900') }
    );
  } catch { return null; }
}

module.exports = router;
module.exports.verifyTOTP = verifyTOTP; // Exported for use in auth.js login
