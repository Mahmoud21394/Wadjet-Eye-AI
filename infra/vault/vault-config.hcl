# ══════════════════════════════════════════════════════════════════
#  Wadjet-Eye AI — HashiCorp Vault Configuration (Phase 1)
#  infra/vault/vault-config.hcl
#
#  Production Vault server configuration.
#  Secrets path layout:
#    secret/wadjet-eye/ai-keys       — LLM API keys (OpenAI, Claude, etc.)
#    secret/wadjet-eye/db            — Database credentials
#    secret/wadjet-eye/jwt           — JWT signing secrets
#    secret/wadjet-eye/integrations  — Third-party API keys (VT, Shodan, etc.)
#    secret/wadjet-eye/mfa           — MFA encryption keys
#    secret/wadjet-eye/kafka         — Kafka SASL credentials
#
#  Auth methods:
#    AppRole — for backend services (Role ID + Secret ID)
#    Kubernetes — for pod service accounts in K8s
#
#  Apply:
#    vault server -config=infra/vault/vault-config.hcl
# ══════════════════════════════════════════════════════════════════

# ── Storage backend ──────────────────────────────────────────────
storage "raft" {
  path    = "/vault/data"
  node_id = "node-1"

  retry_join {
    leader_api_addr = "http://vault-0:8200"
  }
  retry_join {
    leader_api_addr = "http://vault-1:8200"
  }
  retry_join {
    leader_api_addr = "http://vault-2:8200"
  }
}

# ── Listener ─────────────────────────────────────────────────────
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/vault/certs/vault.crt"
  tls_key_file  = "/vault/certs/vault.key"

  # Redirect HTTP to HTTPS
  tls_min_version = "tls12"
  tls_cipher_suites = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"

  # Enable browser UI
  x_forwarded_for_authorized_addrs = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
}

# ── API addr ─────────────────────────────────────────────────────
api_addr     = "https://vault:8200"
cluster_addr = "https://vault:8201"

# ── UI ────────────────────────────────────────────────────────────
ui = true

# ── Telemetry ─────────────────────────────────────────────────────
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}

# ── Seal (auto-unseal via AWS KMS in production) ──────────────────
# Uncomment and configure for production:
# seal "awskms" {
#   region     = "us-east-1"
#   kms_key_id = "alias/vault-unseal"
# }

# ── Log level ─────────────────────────────────────────────────────
log_level   = "Info"
log_format  = "json"
log_file    = "/vault/logs/vault.log"

# ── Cluster ──────────────────────────────────────────────────────
cluster_name = "wadjet-eye-vault"

# ── Disable mlock (needed in containers unless IPC_LOCK) ──────────
disable_mlock = true

# ── Raw storage access (disabled for security) ───────────────────
raw_storage_endpoint = false

# ── Introspection endpoint (disable in production) ───────────────
introspection_endpoint = false
