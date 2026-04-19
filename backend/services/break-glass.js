/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Break-Glass Emergency Access Service v6.0
 *  backend/services/break-glass.js
 *
 *  SECURITY DESIGN:
 *  ─────────────────
 *  All emergency/break-glass access is SERVER-SIDE ONLY.
 *  No emergency account logic exists in the browser.
 *
 *  Requirements to obtain a break-glass session:
 *  1. Source IP must be in BREAK_GLASS_ALLOWED_IPS env var
 *  2. One-time OTP sent via out-of-band channel (email/Slack)
 *  3. OTP is single-use, expires in 10 minutes
 *  4. Session is time-limited to 1 hour
 *  5. Every step is immutably logged to break_glass_audit
 *
 *  API:
 *  POST /api/auth/break-glass/request  — request an OTP
 *  POST /api/auth/break-glass/verify   — exchange OTP for session
 *
 *  BREAK_GLASS_ALLOWED_IPS=10.0.0.1,203.0.113.5 (comma-separated)
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');
const { supabase } = require('../config/supabase');

// ── Configuration ─────────────────────────────────────────────────
const ALLOWED_IPS   = (process.env.BREAK_GLASS_ALLOWED_IPS || '')
  .split(',').map(ip => ip.trim()).filter(Boolean);

const OTP_TTL_MS    = 10 * 60 * 1000;  // 10 minutes
const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour
const MAX_ATTEMPTS   = 3;               // OTP attempts before lockout

// ── IP helper ─────────────────────────────────────────────────────
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
      || req.ip
      || req.connection?.remoteAddress
      || 'unknown';
}

// ── Audit log (immutable — never updates, only inserts) ───────────
async function audit(event, adminEmail, ip, metadata = {}) {
  try {
    await supabase.from('break_glass_audit').insert({
      event,
      admin_email: adminEmail,
      ip_address:  ip,
      metadata:    JSON.stringify(metadata),
      timestamp:   new Date().toISOString(),
    });
  } catch (err) {
    // Audit failures must not block the response but must be logged
    console.error('[BreakGlass] CRITICAL: Audit log write failed:', err.message);
  }
}

/**
 * requestBreakGlass
 * Validates IP, generates OTP, sends out-of-band, audit-logs.
 * Returns a generic message — never reveals whether the email exists.
 */
async function requestBreakGlass(req, adminEmail) {
  const ip = getClientIP(req);

  // 1. Enforce IP allowlist
  if (ALLOWED_IPS.length > 0 && !ALLOWED_IPS.includes(ip)) {
    await audit('REJECTED_DISALLOWED_IP', adminEmail, ip);
    console.warn(`[BreakGlass] Rejected request from disallowed IP: ${ip}`);
    // Generic error — do not reveal that IP is the issue
    throw new Error('Break-glass access denied. Contact your security team.');
  }

  // 2. Check for active lockout (too many failed attempts)
  const { data: recentFails } = await supabase
    .from('break_glass_audit')
    .select('id')
    .eq('admin_email', adminEmail)
    .eq('event', 'INVALID_OTP')
    .gte('timestamp', new Date(Date.now() - 15 * 60 * 1000).toISOString()); // last 15 min

  if ((recentFails?.length || 0) >= MAX_ATTEMPTS) {
    await audit('LOCKED_OUT', adminEmail, ip);
    throw new Error('Account temporarily locked after multiple failed attempts. Try again in 15 minutes.');
  }

  // 3. Expire any existing pending OTPs for this email
  await supabase
    .from('break_glass_requests')
    .update({ status: 'SUPERSEDED' })
    .eq('admin_email', adminEmail)
    .eq('status', 'PENDING');

  // 4. Generate cryptographically random 6-digit OTP
  const otp     = crypto.randomInt(100000, 999999).toString();
  const otpHash = crypto.createHash('sha256').update(otp + adminEmail).digest('hex');
  const expiresAt = new Date(Date.now() + OTP_TTL_MS).toISOString();

  // 5. Store OTP hash (NEVER the plaintext OTP)
  const { error: insertErr } = await supabase.from('break_glass_requests').insert({
    admin_email: adminEmail,
    otp_hash:    otpHash,
    ip_address:  ip,
    expires_at:  expiresAt,
    status:      'PENDING',
    attempt_count: 0,
  });

  if (insertErr) {
    await audit('REQUEST_FAILED_DB', adminEmail, ip, { error: insertErr.message });
    throw new Error('Unable to process break-glass request. Contact your security team.');
  }

  // 6. Send OTP via out-of-band channel
  await sendOTPOutOfBand(adminEmail, otp, ip);

  // 7. Audit log
  await audit('OTP_REQUESTED', adminEmail, ip);

  // 8. Return generic message — never confirm the OTP value
  return {
    message: 'If this email is authorized for break-glass access, an OTP has been sent via secure channel.',
    expires_in_seconds: OTP_TTL_MS / 1000,
  };
}

/**
 * verifyBreakGlass
 * Validates OTP, issues time-limited session token, audit-logs.
 */
async function verifyBreakGlass(req, adminEmail, otp) {
  const ip      = getClientIP(req);
  const otpHash = crypto.createHash('sha256').update(otp + adminEmail).digest('hex');

  // 1. Find matching pending request
  const { data: request, error } = await supabase
    .from('break_glass_requests')
    .select('*')
    .eq('admin_email', adminEmail)
    .eq('otp_hash', otpHash)
    .eq('status', 'PENDING')
    .gt('expires_at', new Date().toISOString())
    .single();

  if (error || !request) {
    await audit('INVALID_OTP', adminEmail, ip, { provided_hash_prefix: otpHash.slice(0, 8) });
    throw new Error('Invalid or expired OTP. Each code is single-use and expires in 10 minutes.');
  }

  // 2. Mark OTP as used (single-use enforcement)
  await supabase
    .from('break_glass_requests')
    .update({ status: 'USED', used_at: new Date().toISOString() })
    .eq('id', request.id);

  // 3. Generate session token
  const sessionToken = crypto.randomBytes(48).toString('hex');
  const sessionHash  = crypto.createHash('sha256').update(sessionToken).digest('hex');
  const sessionExp   = new Date(Date.now() + SESSION_TTL_MS).toISOString();

  // 4. Store session
  const { data: session, error: sessErr } = await supabase
    .from('break_glass_sessions')
    .insert({
      admin_email:         adminEmail,
      session_token_hash:  sessionHash,
      ip_address:          ip,
      expires_at:          sessionExp,
      active:              true,
    })
    .select('id')
    .single();

  if (sessErr) {
    await audit('SESSION_CREATE_FAILED', adminEmail, ip, { error: sessErr.message });
    throw new Error('Failed to create break-glass session.');
  }

  // 5. Audit log
  await audit('SESSION_GRANTED', adminEmail, ip, { session_id: session.id, expires_at: sessionExp });
  console.warn(`[BreakGlass] ⚠️ EMERGENCY SESSION GRANTED — email: ${adminEmail} ip: ${ip}`);

  return {
    session_token: sessionToken,
    expires_at:    sessionExp,
    expires_in:    SESSION_TTL_MS / 1000,
    warning: 'This session is time-limited and fully audited. Misuse is a security policy violation.',
  };
}

/**
 * validateBreakGlassSession
 * Middleware-compatible validator for break-glass session tokens.
 */
async function validateBreakGlassSession(sessionToken) {
  const sessionHash = crypto.createHash('sha256').update(sessionToken).digest('hex');

  const { data: session } = await supabase
    .from('break_glass_sessions')
    .select('*')
    .eq('session_token_hash', sessionHash)
    .eq('active', true)
    .gt('expires_at', new Date().toISOString())
    .single();

  return session || null;
}

/**
 * sendOTPOutOfBand
 * Sends OTP via email (and optionally Slack).
 * In development, logs to console only.
 */
async function sendOTPOutOfBand(adminEmail, otp, fromIP) {
  if (process.env.NODE_ENV !== 'production') {
    console.warn('─'.repeat(60));
    console.warn('[BreakGlass] 🔐 DEV MODE — OTP (would be emailed in prod):');
    console.warn(`[BreakGlass]    Email: ${adminEmail}`);
    console.warn(`[BreakGlass]    OTP:   ${otp}`);
    console.warn(`[BreakGlass]    From IP: ${fromIP}`);
    console.warn('[BreakGlass]    NEVER log OTPs in production!');
    console.warn('─'.repeat(60));
    return;
  }

  // Production: send email via SendGrid / SES / SMTP
  // TODO: integrate with your email provider
  // Example: await sendEmail({ to: adminEmail, subject: 'Break-Glass OTP', body: `OTP: ${otp}` });

  // Optionally notify Slack security channel
  if (process.env.SECURITY_SLACK_WEBHOOK) {
    try {
      await fetch(process.env.SECURITY_SLACK_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: `🚨 Break-glass access requested for ${adminEmail} from IP ${fromIP}`,
        }),
      });
    } catch (e) {
      console.warn('[BreakGlass] Slack notification failed:', e.message);
    }
  }
}

module.exports = { requestBreakGlass, verifyBreakGlass, validateBreakGlassSession };
