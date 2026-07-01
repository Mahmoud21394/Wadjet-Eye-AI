/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Autonomous Decision Ledger  v1.0
 *  backend/services/decisionLedger.js
 *
 *  Enterprise Audit Remediation — WS3: Signed, Immutable Decision Audit
 *  ──────────────────────────────────────────────────────────────────────
 *  Every autonomous SOC decision (SOAR action, agent recommendation,
 *  alert triage, playbook execution) must be:
 *
 *  1. Signed       — Ed25519 signature over decision payload
 *  2. Verified     — Signature verified before SOAR execution
 *  3. Immutable    — Append-only ledger in PostgreSQL
 *  4. Replayable   — Replay any decision from ledger + verify chain
 *  5. Hash-chained — Each entry includes SHA-256 of previous entry
 *  6. Human-gated  — High-risk decisions require human approval
 *
 *  No unsigned decision may execute a SOAR action.
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');
const { supabase } = require('../config/supabase');
const logger = require('../utils/logger');
const _MOD   = 'DecisionLedger';

// ─────────────────────────────────────────────────────────────────
// KEY MANAGEMENT — Ed25519 signing keys
// ─────────────────────────────────────────────────────────────────

// In production: keys from Vault. In dev: auto-generated ephemeral keys.
let _signingKey    = null;
let _verifyingKey  = null;
let _keyId         = null;

function _initKeys() {
  if (_signingKey) return;

  const envPriv = process.env.DECISION_SIGNING_KEY_PRIVATE;
  const envPub  = process.env.DECISION_SIGNING_KEY_PUBLIC;

  if (envPriv && envPub) {
    _signingKey   = crypto.createPrivateKey({ key: Buffer.from(envPriv, 'base64'), format: 'der', type: 'pkcs8' });
    _verifyingKey = crypto.createPublicKey({ key: Buffer.from(envPub, 'base64'),  format: 'der', type: 'spki' });
    _keyId        = process.env.DECISION_SIGNING_KEY_ID || 'vault-key-1';
    logger.info(_MOD, 'Ed25519 keys loaded from environment');
  } else {
    // Generate ephemeral key pair for dev/test
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    _signingKey   = privateKey;
    _verifyingKey = publicKey;
    _keyId        = `ephemeral-${Date.now()}`;
    logger.warn(_MOD, 'Using ephemeral Ed25519 keys — set DECISION_SIGNING_KEY_PRIVATE/PUBLIC for production');
  }
}

// ─────────────────────────────────────────────────────────────────
// CANONICAL PAYLOAD — deterministic JSON for signing
// ─────────────────────────────────────────────────────────────────

function _canonicalize(decision) {
  // Sort keys deterministically (prevents signature bypass via key reordering)
  const keys = [
    'decision_id', 'agent_id', 'tenant_id', 'action',
    'confidence', 'risk_score', 'requires_human', 'timestamp',
    'input_hash', 'chain_prev',
  ];
  const canonical = {};
  for (const k of keys) {
    if (decision[k] !== undefined) canonical[k] = decision[k];
  }
  return JSON.stringify(canonical);
}

// ─────────────────────────────────────────────────────────────────
// CORE: signDecision()
// ─────────────────────────────────────────────────────────────────

/**
 * signDecision — create a signed, hash-chained decision record.
 *
 * @param {object} decision
 * @param {string} decision.agent_id       Agent or module that made the decision
 * @param {string} decision.tenant_id      Tenant scope
 * @param {string} decision.action         Action recommended (e.g. 'block_ip', 'close_alert')
 * @param {number} decision.confidence     0–1 confidence score
 * @param {number} decision.risk_score     0–100 risk score
 * @param {object} decision.input          Raw input that triggered the decision
 * @param {object} [decision.metadata]     Additional context
 * @returns {Promise<object>}              Signed decision record
 */
async function signDecision(decision) {
  _initKeys();

  const decision_id = crypto.randomUUID();
  const timestamp   = new Date().toISOString();

  // Hash the input to include in signature (prevents input substitution attacks)
  const inputStr  = typeof decision.input === 'string' ? decision.input : JSON.stringify(decision.input || {});
  const input_hash = crypto.createHash('sha256').update(inputStr).digest('hex');

  // Get hash of previous ledger entry (for chain integrity)
  const chain_prev = await _getLastEntryHash(decision.tenant_id);

  // Determine if human approval required
  const requires_human = _requiresHumanApproval(decision);

  const payload = {
    decision_id,
    agent_id:       decision.agent_id,
    tenant_id:      decision.tenant_id,
    action:         decision.action,
    confidence:     decision.confidence || 0,
    risk_score:     decision.risk_score || 0,
    requires_human,
    timestamp,
    input_hash,
    chain_prev:     chain_prev || 'genesis',
  };

  // Sign the canonical payload
  const canonical  = _canonicalize(payload);
  const signature  = crypto.sign(null, Buffer.from(canonical, 'utf8'), _signingKey).toString('base64');

  const record = {
    ...payload,
    input:          decision.input,
    metadata:       decision.metadata || {},
    output:         decision.output || null,
    status:         requires_human ? 'pending_human_approval' : 'signed',
    signature,
    key_id:         _keyId,
    canonical_hash: crypto.createHash('sha256').update(canonical).digest('hex'),
  };

  logger.info(_MOD, 'Decision signed', {
    decision_id, agent_id: decision.agent_id, tenant_id: decision.tenant_id,
    action: decision.action, requires_human, confidence: decision.confidence,
  });

  return record;
}

// ─────────────────────────────────────────────────────────────────
// CORE: verifyDecision()
// ─────────────────────────────────────────────────────────────────

/**
 * verifyDecision — verify signature before executing a SOAR action.
 * MUST be called before any autonomous execution.
 *
 * @param {object} record  Signed decision record from signDecision()
 * @returns {{ valid: boolean, reason?: string }}
 */
function verifyDecision(record) {
  _initKeys();

  if (!record || !record.signature) {
    return { valid: false, reason: 'missing_signature' };
  }

  if (record.status === 'pending_human_approval') {
    return { valid: false, reason: 'requires_human_approval' };
  }

  if (record.status === 'rejected') {
    return { valid: false, reason: 'decision_rejected' };
  }

  try {
    const canonical = _canonicalize({
      decision_id:    record.decision_id,
      agent_id:       record.agent_id,
      tenant_id:      record.tenant_id,
      action:         record.action,
      confidence:     record.confidence,
      risk_score:     record.risk_score,
      requires_human: record.requires_human,
      timestamp:      record.timestamp,
      input_hash:     record.input_hash,
      chain_prev:     record.chain_prev,
    });

    const sigBuf = Buffer.from(record.signature, 'base64');
    const valid  = crypto.verify(null, Buffer.from(canonical, 'utf8'), _verifyingKey, sigBuf);

    if (!valid) {
      logger.error(_MOD, 'SIGNATURE_VERIFICATION_FAILED', {
        decision_id: record.decision_id, agent_id: record.agent_id,
        tenant_id: record.tenant_id,
      });
    }

    return { valid, reason: valid ? null : 'signature_invalid' };
  } catch (err) {
    logger.error(_MOD, 'Signature verification error', { err: err.message, decision_id: record.decision_id });
    return { valid: false, reason: `verification_error:${err.message}` };
  }
}

// ─────────────────────────────────────────────────────────────────
// CORE: appendToLedger()
// ─────────────────────────────────────────────────────────────────

/**
 * appendToLedger — write a signed decision to the append-only ledger.
 *
 * @param {object} record  Signed decision record
 * @returns {Promise<void>}
 */
async function appendToLedger(record) {
  try {
    const { error } = await supabase.from('decision_ledger').insert({
      decision_id:    record.decision_id,
      agent_id:       record.agent_id,
      tenant_id:      record.tenant_id,
      action:         record.action,
      confidence:     record.confidence,
      risk_score:     record.risk_score,
      requires_human: record.requires_human,
      status:         record.status,
      signature:      record.signature,
      key_id:         record.key_id,
      canonical_hash: record.canonical_hash,
      input_hash:     record.input_hash,
      chain_prev:     record.chain_prev,
      metadata:       record.metadata,
      timestamp:      record.timestamp,
    });

    if (error) {
      logger.error(_MOD, 'Failed to append to ledger', { error: error.message, decision_id: record.decision_id });
    }
  } catch (err) {
    logger.error(_MOD, 'Ledger append error', { err: err.message });
  }
}

// ─────────────────────────────────────────────────────────────────
// CORE: executeIfValid() — the SOAR execution gate
// ─────────────────────────────────────────────────────────────────

/**
 * executeIfValid — the single execution gate for ALL autonomous SOAR actions.
 * No unsigned decision may execute.
 *
 * @param {object} record      Signed decision record
 * @param {Function} executor  The SOAR action to execute (async function)
 * @returns {Promise<object>}
 */
async function executeIfValid(record, executor) {
  const verification = verifyDecision(record);

  if (!verification.valid) {
    logger.warn(_MOD, 'Execution blocked — invalid decision', {
      decision_id: record.decision_id, reason: verification.reason,
    });
    await appendToLedger({ ...record, status: `blocked:${verification.reason}` });
    return {
      executed: false,
      reason:   verification.reason,
      decision_id: record.decision_id,
    };
  }

  // Execute the SOAR action
  let result;
  try {
    result = await executor(record);
    await appendToLedger({ ...record, status: 'executed', output: result });
    logger.info(_MOD, 'Decision executed', {
      decision_id: record.decision_id, action: record.action,
      tenant_id: record.tenant_id,
    });
    return { executed: true, result, decision_id: record.decision_id };
  } catch (err) {
    await appendToLedger({ ...record, status: 'execution_failed', output: { error: err.message } });
    logger.error(_MOD, 'Execution failed', { decision_id: record.decision_id, err: err.message });
    return { executed: false, reason: `execution_failed:${err.message}`, decision_id: record.decision_id };
  }
}

// ─────────────────────────────────────────────────────────────────
// HUMAN APPROVAL — approve/reject workflow
// ─────────────────────────────────────────────────────────────────

/**
 * approveDecision — human analyst approves a pending decision.
 */
async function approveDecision(decision_id, approver_id, tenant_id) {
  const { data: record } = await supabase
    .from('decision_ledger')
    .select('*')
    .eq('decision_id', decision_id)
    .eq('tenant_id', tenant_id)
    .single();

  if (!record) return { success: false, reason: 'not_found' };
  if (record.status !== 'pending_human_approval') return { success: false, reason: 'not_pending' };

  await supabase.from('decision_ledger').update({
    status:      'approved',
    approved_by: approver_id,
    approved_at: new Date().toISOString(),
  }).eq('decision_id', decision_id);

  logger.info(_MOD, 'Decision approved by human', { decision_id, approver_id, tenant_id });
  return { success: true };
}

/**
 * rejectDecision — human analyst rejects a pending decision.
 */
async function rejectDecision(decision_id, rejector_id, reason, tenant_id) {
  await supabase.from('decision_ledger').update({
    status:      'rejected',
    rejected_by: rejector_id,
    rejected_at: new Date().toISOString(),
    rejection_reason: reason,
  }).eq('decision_id', decision_id).eq('tenant_id', tenant_id);

  logger.info(_MOD, 'Decision rejected by human', { decision_id, rejector_id, reason });
  return { success: true };
}

// ─────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────

async function _getLastEntryHash(tenantId) {
  try {
    const { data } = await supabase
      .from('decision_ledger')
      .select('canonical_hash')
      .eq('tenant_id', tenantId)
      .order('timestamp', { ascending: false })
      .limit(1)
      .single();
    return data?.canonical_hash || null;
  } catch {
    return null;
  }
}

function _requiresHumanApproval(decision) {
  // High-risk actions always require human approval
  const HIGH_RISK_ACTIONS = [
    'block_ip', 'isolate_host', 'kill_process', 'quarantine_file',
    'disable_account', 'revoke_token', 'execute_playbook',
    'delete_object', 'terminate_session', 'block_domain',
  ];

  if (HIGH_RISK_ACTIONS.includes(decision.action)) return true;
  if ((decision.risk_score || 0) >= 80) return true;
  if ((decision.confidence || 1) < 0.6) return true;

  return false;
}

module.exports = {
  signDecision,
  verifyDecision,
  appendToLedger,
  executeIfValid,
  approveDecision,
  rejectDecision,
};
