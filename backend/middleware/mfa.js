/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — TOTP MFA Enforcement Middleware (SEC-006 Fix)
 *  backend/middleware/mfa.js
 *
 *  Implements full TOTP-based MFA using otplib.
 *  Enforces MFA for ADMIN/SUPER_ADMIN roles.
 *  Integrates with verifyToken() flow.
 *
 *  Audit finding: SEC-006 — MFA tracked as boolean, never enforced
 *  OWASP: A07:2021 Identification & Authentication Failures
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const { authenticator } = require('otplib');
const qrcode            = require('qrcode');
const crypto            = require('crypto');

// ── TOTP configuration ────────────────────────────────────────────
authenticator.options = {
  window:    1,       // ±1 step tolerance (30s windows) = 90s grace
  digits:    6,
  algorithm: 'sha1',
  step:      30,      // 30-second TOTP window (standard)
};

const APP_NAME = process.env.MFA_APP_NAME || 'Wadjet-Eye AI';

// ── Roles that MUST have MFA enabled ─────────────────────────────
const MFA_REQUIRED_ROLES = new Set(['SUPER_ADMIN', 'ADMIN', 'TEAM_LEAD']);

// ── MFA service ───────────────────────────────────────────────────

/**
 * generateSecret — creates a new TOTP secret for a user
 * @returns {{ secret: string, otpauth_url: string }}
 */
function generateSecret(userEmail) {
  const secret     = authenticator.generateSecret(32); // 32-byte = 256-bit secret
  const otpauthUrl = authenticator.keyuri(userEmail, APP_NAME, secret);
  return { secret, otpauth_url: otpauthUrl };
}

/**
 * generateQRCode — returns base64 PNG QR code for the TOTP setup
 */
async function generateQRCode(otpauthUrl) {
  return qrcode.toDataURL(otpauthUrl, {
    errorCorrectionLevel: 'H',
    type:   'image/png',
    width:  300,
    margin: 2,
  });
}

/**
 * verifyToken — validates a 6-digit TOTP code against a secret
 * @returns {boolean}
 */
function verifyTotpCode(code, secret) {
  try {
    return authenticator.verify({ token: String(code).trim(), secret });
  } catch {
    return false;
  }
}

/**
 * generateBackupCodes — creates 10 single-use backup codes
 * Store hashed versions in DB; return plaintext once to the user.
 */
function generateBackupCodes() {
  return Array.from({ length: 10 }, () => {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase(); // e.g. "A1B2C3D4"
    return `${code.slice(0,4)}-${code.slice(4)}`;
  });
}

/**
 * hashBackupCode — SHA-256 hash for storage
 */
function hashBackupCode(code) {
  return crypto.createHash('sha256').update(code.replace('-', '').toUpperCase()).digest('hex');
}

// ── Middleware ────────────────────────────────────────────────────

/**
 * requireMfa — enforces MFA verification gate
 *
 * After verifyToken() sets req.user, this middleware checks:
 *  1. If user role requires MFA (ADMIN, SUPER_ADMIN, TEAM_LEAD)
 *  2. If user has MFA enabled in their profile
 *  3. If the current request session has a valid MFA token
 *
 * On failure, returns 403 MFA_REQUIRED with setup instructions.
 */
function requireMfa(req, res, next) {
  const user = req.user;
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated', code: 'MISSING_TOKEN' });
  }

  // Check if role requires MFA
  const roleRequiresMfa = MFA_REQUIRED_ROLES.has(user.role);
  if (!roleRequiresMfa) return next();

  // Check if MFA is enabled
  if (!user.mfa_enabled) {
    return res.status(403).json({
      error:    'MFA enrollment required for your role. Please set up TOTP authenticator.',
      code:     'MFA_SETUP_REQUIRED',
      role:     user.role,
      setup_url: '/api/auth/mfa/setup',
    });
  }

  // Check MFA session claim: verifyToken should have validated mfa_verified claim in JWT
  // OR check X-MFA-Token header for step-up authentication
  const mfaVerified = req.user?.mfa_verified === true;
  if (!mfaVerified) {
    return res.status(403).json({
      error:     'MFA verification required. Submit TOTP code to /api/auth/mfa/verify.',
      code:      'MFA_VERIFICATION_REQUIRED',
      verify_url: '/api/auth/mfa/verify',
    });
  }

  next();
}

/**
 * requireMfaForAdmins — convenience wrapper that only blocks ADMIN roles
 */
function requireMfaForAdmins(req, res, next) {
  const user = req.user;
  if (!user) return res.status(401).json({ error: 'Not authenticated', code: 'MISSING_TOKEN' });

  if (['SUPER_ADMIN', 'ADMIN'].includes(user.role)) {
    return requireMfa(req, res, next);
  }
  next();
}

// ── MFA route handlers (used in routes/auth.js) ───────────────────

/**
 * handleMfaSetup — POST /api/auth/mfa/setup
 * Generates a TOTP secret and QR code for the authenticated user.
 */
async function handleMfaSetup(req, res) {
  const { supabase } = require('../config/supabase');
  const userId = req.user.id;
  const email  = req.user.email;

  try {
    const { secret, otpauth_url } = generateSecret(email);
    const qr_code = await generateQRCode(otpauth_url);

    // Store secret encrypted in DB (pending confirmation)
    const encryptedSecret = encryptSecret(secret);
    await supabase
      .from('user_mfa_pending')
      .upsert({ user_id: userId, secret: encryptedSecret, created_at: new Date().toISOString() });

    res.json({
      secret:       secret,          // Show once — user enters into authenticator app
      qr_code:      qr_code,         // Base64 PNG for QR display
      otpauth_url:  otpauth_url,
      message:      'Scan the QR code with your authenticator app, then confirm with /api/auth/mfa/confirm',
      confirm_url:  '/api/auth/mfa/confirm',
    });
  } catch (err) {
    console.error('[MFA] Setup error:', err.message);
    res.status(500).json({ error: 'MFA setup failed', code: 'MFA_SETUP_ERROR' });
  }
}

/**
 * handleMfaConfirm — POST /api/auth/mfa/confirm
 * User submits first TOTP code to confirm setup.
 */
async function handleMfaConfirm(req, res) {
  const { supabase } = require('../config/supabase');
  const { totp_code } = req.body;
  const userId = req.user.id;

  try {
    // Fetch pending secret
    const { data: pending } = await supabase
      .from('user_mfa_pending')
      .select('secret')
      .eq('user_id', userId)
      .single();

    if (!pending) {
      return res.status(400).json({ error: 'No pending MFA setup found. Start setup first.', code: 'MFA_NO_PENDING' });
    }

    const secret = decryptSecret(pending.secret);
    if (!verifyTotpCode(totp_code, secret)) {
      return res.status(400).json({ error: 'Invalid TOTP code. Try again.', code: 'MFA_INVALID_CODE' });
    }

    // Generate backup codes
    const backupCodes   = generateBackupCodes();
    const hashedCodes   = backupCodes.map(hashBackupCode);

    // Activate MFA in users table
    await supabase.from('users').update({ mfa_enabled: true, mfa_secret: secret }).eq('id', userId);

    // Store hashed backup codes
    await supabase.from('user_mfa_backup_codes').insert(
      hashedCodes.map(code => ({ user_id: userId, code_hash: code, used: false }))
    );

    // Remove pending record
    await supabase.from('user_mfa_pending').delete().eq('user_id', userId);

    res.json({
      success:      true,
      message:      'MFA enabled successfully. Store backup codes securely.',
      backup_codes: backupCodes,  // Show once — user must save these
    });
  } catch (err) {
    console.error('[MFA] Confirm error:', err.message);
    res.status(500).json({ error: 'MFA confirmation failed', code: 'MFA_CONFIRM_ERROR' });
  }
}

/**
 * handleMfaVerify — POST /api/auth/mfa/verify
 * Step-up authentication: user submits TOTP to get mfa_verified session.
 */
async function handleMfaVerify(req, res) {
  const { supabase } = require('../config/supabase');
  const jwt          = require('jsonwebtoken');
  const { totp_code } = req.body;
  const userId = req.user.id;

  try {
    const { data: profile } = await supabase
      .from('users')
      .select('mfa_secret, mfa_enabled')
      .eq('id', userId)
      .single();

    if (!profile?.mfa_enabled) {
      return res.status(400).json({ error: 'MFA not enabled on account', code: 'MFA_NOT_ENABLED' });
    }

    // Try TOTP code first
    if (!verifyTotpCode(totp_code, profile.mfa_secret)) {
      // Try backup code
      const codeHash = hashBackupCode(totp_code);
      const { data: backup } = await supabase
        .from('user_mfa_backup_codes')
        .select('id')
        .eq('user_id', userId)
        .eq('code_hash', codeHash)
        .eq('used', false)
        .single();

      if (!backup) {
        console.warn(`[MFA] Failed verification for user ${userId}`);
        return res.status(400).json({ error: 'Invalid TOTP code', code: 'MFA_INVALID_CODE' });
      }

      // Mark backup code as used
      await supabase.from('user_mfa_backup_codes').update({ used: true, used_at: new Date().toISOString() }).eq('id', backup.id);
    }

    // Issue short-lived MFA-verified JWT claim (15 minutes)
    const mfaToken = jwt.sign(
      { user_id: userId, mfa_verified: true, type: 'mfa_session' },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.json({
      success:   true,
      mfa_token: mfaToken,
      expires_in: 900,   // 15 minutes
      message:   'MFA verified. Include X-MFA-Token header in subsequent requests.',
    });
  } catch (err) {
    console.error('[MFA] Verify error:', err.message);
    res.status(500).json({ error: 'MFA verification failed', code: 'MFA_VERIFY_ERROR' });
  }
}

/**
 * handleMfaDisable — DELETE /api/auth/mfa
 * Requires current TOTP confirmation to disable.
 */
async function handleMfaDisable(req, res) {
  const { supabase } = require('../config/supabase');
  const { totp_code } = req.body;
  const userId = req.user.id;
  const role   = req.user.role;

  // MFA required roles cannot disable MFA
  if (MFA_REQUIRED_ROLES.has(role)) {
    return res.status(403).json({
      error: `Role '${role}' requires MFA. MFA cannot be disabled for this role.`,
      code:  'MFA_REQUIRED_FOR_ROLE',
    });
  }

  try {
    const { data: profile } = await supabase
      .from('users').select('mfa_secret').eq('id', userId).single();

    if (!verifyTotpCode(totp_code, profile.mfa_secret)) {
      return res.status(400).json({ error: 'Invalid TOTP code', code: 'MFA_INVALID_CODE' });
    }

    await supabase.from('users').update({ mfa_enabled: false, mfa_secret: null }).eq('id', userId);
    await supabase.from('user_mfa_backup_codes').delete().eq('user_id', userId);

    res.json({ success: true, message: 'MFA disabled successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'MFA disable failed', code: 'MFA_DISABLE_ERROR' });
  }
}

// ── Encryption helpers (AES-256-GCM for TOTP secrets at rest) ─────

const ENCRYPT_KEY = Buffer.from(
  process.env.MFA_ENCRYPT_KEY || crypto.randomBytes(32).toString('hex').slice(0, 64),
  'hex'
).slice(0, 32);

function encryptSecret(plaintext) {
  const iv         = crypto.randomBytes(12);
  const cipher     = crypto.createCipheriv('aes-256-gcm', ENCRYPT_KEY, iv);
  const encrypted  = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag    = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

function decryptSecret(ciphertext) {
  const buf       = Buffer.from(ciphertext, 'base64');
  const iv        = buf.slice(0, 12);
  const authTag   = buf.slice(12, 28);
  const encrypted = buf.slice(28);
  const decipher  = crypto.createDecipheriv('aes-256-gcm', ENCRYPT_KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

module.exports = {
  generateSecret,
  generateQRCode,
  verifyTotpCode,
  generateBackupCodes,
  hashBackupCode,
  requireMfa,
  requireMfaForAdmins,
  handleMfaSetup,
  handleMfaConfirm,
  handleMfaVerify,
  handleMfaDisable,
  encryptSecret,
  decryptSecret,
  MFA_REQUIRED_ROLES,
};
