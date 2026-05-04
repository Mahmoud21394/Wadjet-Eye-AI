/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Centralized Configuration
 *  backend/config/index.js
 *
 *  Single source of truth for all runtime configuration.
 *  Reads from environment variables with safe defaults.
 *  Integrated with HashiCorp Vault for secret rotation.
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const path = require('path');

// ── Derived helpers ───────────────────────────────────────────────
const isProd = process.env.NODE_ENV === 'production';
const isDev  = !isProd;

const config = {
  env: process.env.NODE_ENV || 'development',
  isProd,
  isDev,

  server: {
    port:           parseInt(process.env.PORT, 10) || 4000,
    host:           process.env.HOST || '0.0.0.0',
    trustProxy:     isProd ? 1 : false,
    requestTimeout: parseInt(process.env.REQUEST_TIMEOUT_MS, 10) || 30000,
    bodyLimit:      process.env.BODY_LIMIT || '2mb',
  },

  cors: {
    allowedOrigins: (process.env.CORS_ALLOWED_ORIGINS || [
      'https://wadjet-eye-ai.vercel.app',
      'https://www.genspark.ai',
      'https://wadjet-eye.io',
      'https://app.wadjet-eye.io',
      'http://localhost:3000',
      'http://localhost:5173',
    ].join(',')).split(',').map(s => s.trim()).filter(Boolean),
  },

  jwt: {
    secret:          process.env.JWT_SECRET || '',
    accessTtl:       process.env.JWT_ACCESS_TTL  || '15m',
    refreshTtl:      process.env.JWT_REFRESH_TTL || '7d',
    issuer:          process.env.JWT_ISSUER  || 'wadjet-eye-ai',
    audience:        process.env.JWT_AUDIENCE || 'wadjet-eye-users',
  },

  supabase: {
    url:        process.env.SUPABASE_URL            || '',
    serviceKey: process.env.SUPABASE_SERVICE_KEY    || '',
    anonKey:    process.env.SUPABASE_ANON_KEY        || '',
  },

  redis: {
    url:              process.env.REDIS_URL || 'redis://localhost:6379',
    password:         process.env.REDIS_PASSWORD || undefined,
    tls:              process.env.REDIS_TLS === 'true',
    connectTimeout:   parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS, 10) || 5000,
    maxRetriesPerReq: 3,
  },

  kafka: {
    brokers:      (process.env.KAFKA_BROKERS || 'kafka:9092').split(','),
    clientId:     process.env.KAFKA_CLIENT_ID   || 'wadjet-eye-api',
    ssl:          process.env.KAFKA_SSL          === 'true',
    sasl: process.env.KAFKA_SASL_USERNAME ? {
      mechanism: process.env.KAFKA_SASL_MECHANISM || 'scram-sha-256',
      username:  process.env.KAFKA_SASL_USERNAME,
      password:  process.env.KAFKA_SASL_PASSWORD,
    } : undefined,
  },

  vault: {
    addr:       process.env.VAULT_ADDR         || 'http://vault:8200',
    token:      process.env.VAULT_TOKEN        || '',
    roleId:     process.env.VAULT_ROLE_ID      || '',
    secretId:   process.env.VAULT_SECRET_ID    || '',
    namespace:  process.env.VAULT_NAMESPACE    || '',
    mount:      process.env.VAULT_KV_MOUNT     || 'secret',
    appPath:    process.env.VAULT_APP_PATH     || 'wadjet-eye',
    enabled:    process.env.VAULT_ENABLED      === 'true',
    renewTtl:   parseInt(process.env.VAULT_RENEW_TTL_S, 10) || 3600,
  },

  mfa: {
    issuer:        process.env.MFA_ISSUER    || 'Wadjet-Eye AI',
    algorithm:     'SHA1',
    digits:        6,
    period:        30,
    backupCodes:   parseInt(process.env.MFA_BACKUP_CODES, 10) || 10,
    enforceForAll: process.env.MFA_ENFORCE_ALL === 'true',
  },

  rateLimit: {
    windowMs:      parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60_000,
    max:           parseInt(process.env.RATE_LIMIT_MAX, 10)        || 100,
    llmWindowMs:   parseInt(process.env.LLM_RATE_WINDOW_MS, 10)   || 60_000,
    llmMax:        parseInt(process.env.LLM_RATE_MAX, 10)          || 20,
    authWindowMs:  parseInt(process.env.AUTH_RATE_WINDOW_MS, 10)  || 900_000,
    authMax:       parseInt(process.env.AUTH_RATE_MAX, 10)         || 10,
  },

  neo4j: {
    uri:      process.env.NEO4J_URI      || 'bolt://neo4j:7687',
    username: process.env.NEO4J_USERNAME || 'neo4j',
    password: process.env.NEO4J_PASSWORD || 'password',
    database: process.env.NEO4J_DATABASE || 'neo4j',
  },

  pinecone: {
    apiKey:      process.env.PINECONE_API_KEY  || '',
    environment: process.env.PINECONE_ENV      || 'us-east-1-aws',
    index:       process.env.PINECONE_INDEX    || 'wadjet-threat-intel',
    dimension:   parseInt(process.env.PINECONE_DIM, 10) || 1536,
  },

  openai: {
    apiKey:       process.env.OPENAI_API_KEY    || process.env.RAKAY_OPENAI_KEY || '',
    model:        process.env.OPENAI_MODEL       || 'gpt-4o',
    embeddingModel: process.env.OPENAI_EMBED_MODEL || 'text-embedding-3-small',
    maxTokens:    parseInt(process.env.OPENAI_MAX_TOKENS, 10) || 4096,
    temperature:  parseFloat(process.env.OPENAI_TEMPERATURE) || 0.2,
  },

  anthropic: {
    apiKey: process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY || process.env.RAKAY_API_KEY || '',
    model:  process.env.ANTHROPIC_MODEL   || 'claude-3-5-sonnet-20241022',
  },

  ai: {
    defaultProvider: process.env.AI_DEFAULT_PROVIDER || 'openai',
    ragTopK:         parseInt(process.env.RAG_TOP_K, 10) || 5,
    ragMinScore:     parseFloat(process.env.RAG_MIN_SCORE) || 0.72,
    memoryTtlMs:     parseInt(process.env.AI_MEMORY_TTL_MS, 10) || 3_600_000,
    maxHistory:      parseInt(process.env.AI_MAX_HISTORY, 10)   || 20,
  },

  threatIntel: {
    virusTotalKey:   process.env.VIRUSTOTAL_API_KEY   || '',
    abuseIpdbKey:    process.env.ABUSEIPDB_API_KEY     || '',
    shodanKey:       process.env.SHODAN_API_KEY         || '',
    otxKey:          process.env.OTX_API_KEY            || '',
    misp:            process.env.MISP_URL               || '',
    mispKey:         process.env.MISP_API_KEY           || '',
  },

  reporting: {
    outputDir:   process.env.REPORTS_DIR || path.join(__dirname, '../../reports'),
    retentionDays: parseInt(process.env.REPORTS_RETENTION_DAYS, 10) || 90,
    pdfEngine:   process.env.PDF_ENGINE || 'puppeteer',
  },

  metrics: {
    prometheusPort: parseInt(process.env.PROMETHEUS_PORT, 10) || 9090,
    enabled:        process.env.METRICS_ENABLED !== 'false',
  },

  logging: {
    level:   process.env.LOG_LEVEL   || (isProd ? 'info' : 'debug'),
    format:  process.env.LOG_FORMAT  || (isProd ? 'json' : 'pretty'),
    auditRetentionDays: parseInt(process.env.AUDIT_RETENTION_DAYS, 10) || 365,
  },

  csrf: {
    secret:  process.env.CSRF_SECRET || process.env.JWT_SECRET || '',
    ttl:     parseInt(process.env.CSRF_TTL_S, 10) || 3600,
  },

  darkweb: {
    torProxy:  process.env.TOR_PROXY_URL || 'socks5://tor:9050',
    enabled:   process.env.DARKWEB_ENABLED === 'true',
    scanInterval: parseInt(process.env.DARKWEB_SCAN_INTERVAL_MS, 10) || 3_600_000,
  },

  gdelt: {
    apiBase: 'https://api.gdeltproject.org/api/v2',
    enabled: process.env.GDELT_ENABLED !== 'false',
  },

  splunk: {
    hecUrl:   process.env.SPLUNK_HEC_URL   || '',
    hecToken: process.env.SPLUNK_HEC_TOKEN || '',
    index:    process.env.SPLUNK_INDEX     || 'main',
  },

  sentinel: {
    workspaceId:  process.env.SENTINEL_WORKSPACE_ID  || '',
    primaryKey:   process.env.SENTINEL_PRIMARY_KEY   || '',
    logType:      process.env.SENTINEL_LOG_TYPE       || 'WadjetEyeAlert',
  },

  taxii: {
    server:   process.env.TAXII_SERVER   || '',
    username: process.env.TAXII_USERNAME || '',
    password: process.env.TAXII_PASSWORD || '',
    collection: process.env.TAXII_COLLECTION || 'wadjet-eye-ti',
  },
};

// ── Validation ────────────────────────────────────────────────────
function validate() {
  const errors = [];
  if (isProd && !config.jwt.secret) errors.push('JWT_SECRET is required in production');
  if (isProd && config.jwt.secret.length < 32) errors.push('JWT_SECRET must be >= 32 characters in production');
  if (isProd && config.csrf.secret.length < 32) errors.push('CSRF_SECRET must be >= 32 characters in production');
  return errors;
}

config.validate = validate;
module.exports = config;
