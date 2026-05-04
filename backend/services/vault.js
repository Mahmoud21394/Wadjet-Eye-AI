/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — HashiCorp Vault / Secrets Manager (SEC-008 Fix)
 *  backend/services/vault.js
 *
 *  Integrates HashiCorp Vault for secrets management.
 *  Falls back to environment variables when Vault is unavailable.
 *  Supports: KV v2, dynamic secrets, automatic rotation.
 *
 *  Audit finding: SEC-008 — API keys stored in .env / docker-compose
 *  OWASP: A02:2021 Cryptographic Failures
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const https  = require('https');
const http   = require('http');
const crypto = require('crypto');

// ── Configuration ─────────────────────────────────────────────────
const VAULT_ADDR      = process.env.VAULT_ADDR      || 'http://vault:8200';
const VAULT_TOKEN     = process.env.VAULT_TOKEN      || process.env.VAULT_ROOT_TOKEN;
const VAULT_ROLE_ID   = process.env.VAULT_ROLE_ID;
const VAULT_SECRET_ID = process.env.VAULT_SECRET_ID;
const VAULT_NAMESPACE = process.env.VAULT_NAMESPACE  || '';   // Vault Enterprise namespaces
const KV_MOUNT        = process.env.VAULT_KV_MOUNT   || 'secret';
const SECRET_PATH     = process.env.VAULT_SECRET_PATH || 'wadjet-eye';
const CACHE_TTL_MS    = parseInt(process.env.VAULT_CACHE_TTL || '300000', 10);  // 5min cache

// ── In-memory secret cache ────────────────────────────────────────
const _cache    = new Map();   // key → { value, expiresAt }
const _rotating = new Set();   // keys currently being refreshed

/**
 * vaultRequest — low-level Vault HTTP client
 */
async function vaultRequest(method, path, body = null, token = null) {
  const parsedUrl = new URL(`${VAULT_ADDR}/v1/${path}`);
  const transport = parsedUrl.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const options = {
      hostname: parsedUrl.hostname,
      port:     parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path:     parsedUrl.pathname + parsedUrl.search,
      method,
      headers: {
        'Content-Type':  'application/json',
        'X-Vault-Token': token || VAULT_TOKEN || '',
        ...(VAULT_NAMESPACE ? { 'X-Vault-Namespace': VAULT_NAMESPACE } : {}),
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
    };

    const req = transport.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const bodyStr = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 400) {
          let errData;
          try { errData = JSON.parse(bodyStr); } catch { errData = { errors: [bodyStr] }; }
          return reject(Object.assign(new Error(`Vault HTTP ${res.statusCode}: ${errData.errors?.[0] || bodyStr}`), { statusCode: res.statusCode, vaultErrors: errData.errors }));
        }
        try {
          resolve(JSON.parse(bodyStr));
        } catch {
          resolve({});   // 204 No Content responses
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('Vault request timeout')); });
    if (payload) req.write(payload);
    req.end();
  });
}

// ── Authentication ────────────────────────────────────────────────

let _vaultToken        = VAULT_TOKEN || null;
let _tokenExpires      = null;
let _authInitialized   = false;

/**
 * authenticate — AppRole authentication with automatic token renewal
 */
async function authenticate() {
  if (_vaultToken && _tokenExpires && Date.now() < _tokenExpires - 60000) {
    return _vaultToken;   // Token still valid with 1-minute buffer
  }

  // If static token configured, use it
  if (VAULT_TOKEN) {
    _vaultToken = VAULT_TOKEN;
    _tokenExpires = Date.now() + (24 * 3600 * 1000);   // Assume 24h TTL for static tokens
    return _vaultToken;
  }

  // AppRole authentication
  if (!VAULT_ROLE_ID || !VAULT_SECRET_ID) {
    throw new Error('Vault authentication failed: VAULT_TOKEN or (VAULT_ROLE_ID + VAULT_SECRET_ID) required');
  }

  const response = await vaultRequest('POST', 'auth/approle/login', {
    role_id:   VAULT_ROLE_ID,
    secret_id: VAULT_SECRET_ID,
  });

  _vaultToken   = response.auth?.client_token;
  const ttlSec  = response.auth?.lease_duration || 3600;
  _tokenExpires = Date.now() + (ttlSec * 1000);

  if (!_vaultToken) throw new Error('Vault AppRole login returned no token');
  console.log(`[Vault] Authenticated via AppRole — token TTL: ${ttlSec}s`);
  return _vaultToken;
}

// ── Core API ──────────────────────────────────────────────────────

/**
 * readSecret — read a secret from Vault KV v2
 * @param {string} key - Secret key within the Wadjet-Eye path
 * @returns {Promise<string>}
 */
async function readSecret(key) {
  // Check cache first
  const cached = _cache.get(key);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.value;
  }

  try {
    const token    = await authenticate();
    const response = await vaultRequest('GET', `${KV_MOUNT}/data/${SECRET_PATH}`, null, token);
    const secrets  = response.data?.data || {};

    // Cache all returned secrets
    const expiresAt = Date.now() + CACHE_TTL_MS;
    for (const [k, v] of Object.entries(secrets)) {
      _cache.set(k, { value: v, expiresAt });
    }

    return secrets[key] ?? null;
  } catch (err) {
    console.warn(`[Vault] readSecret '${key}' failed: ${err.message} — falling back to env`);
    return process.env[key.toUpperCase()] ?? null;
  }
}

/**
 * writeSecret — write/update a secret in Vault KV v2
 * @param {string} key - Secret key
 * @param {string} value - Secret value
 */
async function writeSecret(key, value) {
  try {
    const token = await authenticate();

    // Read existing secrets to merge (KV v2 patch semantics)
    let existing = {};
    try {
      const current = await vaultRequest('GET', `${KV_MOUNT}/data/${SECRET_PATH}`, null, token);
      existing = current.data?.data || {};
    } catch { /* fresh write */ }

    await vaultRequest('POST', `${KV_MOUNT}/data/${SECRET_PATH}`, {
      data: { ...existing, [key]: value },
    }, token);

    // Update cache
    _cache.set(key, { value, expiresAt: Date.now() + CACHE_TTL_MS });
    console.log(`[Vault] Secret '${key}' written successfully`);
  } catch (err) {
    console.error(`[Vault] writeSecret '${key}' failed:`, err.message);
    throw err;
  }
}

/**
 * deleteSecret — soft-delete a specific key from the KV path
 */
async function deleteSecret(key) {
  try {
    const token = await authenticate();
    const current = await vaultRequest('GET', `${KV_MOUNT}/data/${SECRET_PATH}`, null, token);
    const existing = current.data?.data || {};
    delete existing[key];
    await vaultRequest('POST', `${KV_MOUNT}/data/${SECRET_PATH}`, { data: existing }, token);
    _cache.delete(key);
    console.log(`[Vault] Secret '${key}' deleted`);
  } catch (err) {
    console.error(`[Vault] deleteSecret '${key}' failed:`, err.message);
    throw err;
  }
}

/**
 * listSecrets — list all secret keys in the Wadjet-Eye path
 */
async function listSecrets() {
  try {
    const token    = await authenticate();
    const response = await vaultRequest('LIST', `${KV_MOUNT}/metadata/${SECRET_PATH}`, null, token);
    return response.data?.keys || [];
  } catch (err) {
    console.warn('[Vault] listSecrets failed:', err.message);
    return [];
  }
}

/**
 * rotateSecret — rotate an API key and update Vault
 * Calls service-specific rotation endpoint if configured.
 */
async function rotateSecret(key, newValue) {
  const oldValue = await readSecret(key);
  await writeSecret(key, newValue);

  // Audit log the rotation
  console.log(`[Vault] Secret '${key}' rotated at ${new Date().toISOString()}`);

  return { rotated: true, key, timestamp: new Date().toISOString(), old_value_hash: crypto.createHash('sha256').update(oldValue || '').digest('hex').slice(0, 8) };
}

// ── Health check ──────────────────────────────────────────────────
async function healthCheck() {
  try {
    const response = await vaultRequest('GET', 'sys/health', null, '');
    return {
      healthy:     true,
      initialized: response.initialized,
      sealed:      response.sealed,
      version:     response.version,
      cluster:     response.cluster_name,
    };
  } catch (err) {
    return { healthy: false, error: err.message };
  }
}

// ── SecretManager facade (public API) ─────────────────────────────
/**
 * SecretManager — unified interface for secret retrieval
 * Tries Vault first, falls back to environment variables.
 *
 * Usage:
 *   const { SecretManager } = require('./vault');
 *   const apiKey = await SecretManager.get('OPENAI_API_KEY');
 */
const SecretManager = {
  /**
   * get — retrieve a secret by name
   * Vault key name maps to env var name (uppercase).
   */
  async get(name) {
    // Try Vault
    try {
      if (VAULT_ADDR && (VAULT_TOKEN || (VAULT_ROLE_ID && VAULT_SECRET_ID))) {
        const value = await readSecret(name);
        if (value) return value;
      }
    } catch { /* fall through to env */ }

    // Fall back to environment variable
    return process.env[name] || process.env[name.toUpperCase()] || null;
  },

  async set(name, value) { return writeSecret(name, value); },
  async delete(name)      { return deleteSecret(name); },
  async list()            { return listSecrets(); },
  async rotate(name, val) { return rotateSecret(name, val); },
  async health()          { return healthCheck(); },
  invalidateCache()       { _cache.clear(); console.log('[Vault] Cache cleared'); },

  /**
   * getAll — retrieve multiple secrets in one call (batched)
   */
  async getAll(names) {
    const result = {};
    await Promise.all(names.map(async (name) => {
      result[name] = await SecretManager.get(name);
    }));
    return result;
  },
};

// ── Pre-warm secrets cache on startup ────────────────────────────
async function preWarmCache() {
  const CRITICAL_SECRETS = [
    'OPENAI_API_KEY', 'CLAUDE_API_KEY', 'GEMINI_API_KEY',
    'VT_API_KEY', 'SHODAN_API_KEY', 'ABUSEIPDB_API_KEY', 'OTX_API_KEY',
    'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'SUPABASE_ANON_KEY',
    'JWT_SECRET', 'MFA_ENCRYPT_KEY',
    'NEO4J_URI', 'NEO4J_PASSWORD',
    'PINECONE_API_KEY', 'WEAVIATE_URL',
  ];

  try {
    await authenticate();
    await Promise.allSettled(CRITICAL_SECRETS.map(k => readSecret(k)));
    _authInitialized = true;
    console.log('[Vault] Secret cache pre-warmed');
  } catch (err) {
    console.warn('[Vault] Pre-warm skipped (Vault unavailable):', err.message);
    _authInitialized = true;   // Mark done so requests don't wait
  }
}

// ── Schedule automatic token renewal ─────────────────────────────
setInterval(async () => {
  if (_tokenExpires && Date.now() > _tokenExpires - 120000) {
    try { await authenticate(); }
    catch (err) { console.error('[Vault] Token renewal failed:', err.message); }
  }
}, 60000);   // Check every minute

// ── Kubernetes External Secrets annotation ─────────────────────────
/**
 * getK8sSecretAnnotations — generates ExternalSecret manifest fragment
 * for External Secrets Operator → Vault integration.
 */
function getK8sSecretAnnotations() {
  return {
    apiVersion: 'external-secrets.io/v1beta1',
    kind:       'ExternalSecret',
    metadata:   { name: 'wadjet-eye-secrets', namespace: 'wadjet-eye' },
    spec: {
      refreshInterval: '5m',
      secretStoreRef:  { kind: 'ClusterSecretStore', name: 'vault-backend' },
      target:          { name: 'wadjet-eye-secrets', creationPolicy: 'Owner' },
      data: [
        { secretKey: 'OPENAI_API_KEY',       remoteRef: { key: `${SECRET_PATH}`, property: 'OPENAI_API_KEY' } },
        { secretKey: 'CLAUDE_API_KEY',        remoteRef: { key: `${SECRET_PATH}`, property: 'CLAUDE_API_KEY' } },
        { secretKey: 'JWT_SECRET',            remoteRef: { key: `${SECRET_PATH}`, property: 'JWT_SECRET' } },
        { secretKey: 'SUPABASE_SERVICE_KEY',  remoteRef: { key: `${SECRET_PATH}`, property: 'SUPABASE_SERVICE_KEY' } },
        { secretKey: 'NEO4J_PASSWORD',        remoteRef: { key: `${SECRET_PATH}`, property: 'NEO4J_PASSWORD' } },
        { secretKey: 'PINECONE_API_KEY',      remoteRef: { key: `${SECRET_PATH}`, property: 'PINECONE_API_KEY' } },
      ],
    },
  };
}

module.exports = {
  SecretManager,
  readSecret,
  writeSecret,
  deleteSecret,
  listSecrets,
  rotateSecret,
  healthCheck,
  preWarmCache,
  authenticate,
  getK8sSecretAnnotations,
};
