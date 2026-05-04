#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  Wadjet-Eye AI — Vault Bootstrap Script (Phase 1)
#  infra/vault/vault-init.sh
#
#  Run ONCE after vault-config.hcl starts the server:
#    ./infra/vault/vault-init.sh
#
#  Performs:
#  1. Initialize Vault (5 key shares, threshold 3)
#  2. Unseal with first 3 keys
#  3. Enable KV v2 at secret/
#  4. Enable AppRole auth
#  5. Enable Kubernetes auth
#  6. Create wadjet-eye policy
#  7. Create AppRole for backend service
#  8. Seed initial secrets placeholders
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
INIT_OUTPUT_FILE="/vault/init-keys.json"

export VAULT_ADDR

echo "══════════════════════════════════════════"
echo " Wadjet-Eye Vault Bootstrap"
echo " VAULT_ADDR: $VAULT_ADDR"
echo "══════════════════════════════════════════"

# ── Step 1: Initialize ────────────────────────────────────────────
echo "[1/8] Initializing Vault..."
if vault status 2>&1 | grep -q "Initialized.*true"; then
  echo "  ✓ Vault already initialized — skipping init"
else
  vault operator init \
    -key-shares=5 \
    -key-threshold=3 \
    -format=json > "$INIT_OUTPUT_FILE"
  echo "  ✓ Vault initialized — keys written to $INIT_OUTPUT_FILE"
  echo "  ⚠️  SAVE THESE KEYS SECURELY AND DELETE THE FILE AFTER"
fi

# ── Step 2: Unseal ────────────────────────────────────────────────
echo "[2/8] Unsealing Vault..."
if vault status 2>&1 | grep -q "Sealed.*false"; then
  echo "  ✓ Vault already unsealed"
else
  if [ -f "$INIT_OUTPUT_FILE" ]; then
    KEY1=$(jq -r '.unseal_keys_b64[0]' "$INIT_OUTPUT_FILE")
    KEY2=$(jq -r '.unseal_keys_b64[1]' "$INIT_OUTPUT_FILE")
    KEY3=$(jq -r '.unseal_keys_b64[2]' "$INIT_OUTPUT_FILE")
    vault operator unseal "$KEY1"
    vault operator unseal "$KEY2"
    vault operator unseal "$KEY3"
    echo "  ✓ Vault unsealed"
  else
    echo "  ✗ Cannot unseal — $INIT_OUTPUT_FILE not found. Provide keys manually."
    exit 1
  fi
fi

# ── Authenticate as root ──────────────────────────────────────────
ROOT_TOKEN=$(jq -r '.root_token' "$INIT_OUTPUT_FILE" 2>/dev/null || echo "$VAULT_TOKEN")
export VAULT_TOKEN="$ROOT_TOKEN"

# ── Step 3: Enable KV v2 ─────────────────────────────────────────
echo "[3/8] Enabling KV v2 secrets engine..."
vault secrets enable -path=secret kv-v2 2>/dev/null || echo "  ✓ KV already enabled"

# ── Step 4: Enable AppRole auth ───────────────────────────────────
echo "[4/8] Enabling AppRole auth..."
vault auth enable approle 2>/dev/null || echo "  ✓ AppRole already enabled"

# ── Step 5: Enable Kubernetes auth ───────────────────────────────
echo "[5/8] Enabling Kubernetes auth..."
vault auth enable kubernetes 2>/dev/null || echo "  ✓ Kubernetes auth already enabled"

vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc:443" \
  token_reviewer_jwt="@/var/run/secrets/kubernetes.io/serviceaccount/token" \
  kubernetes_ca_cert="@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" \
  2>/dev/null || echo "  ✓ K8s config (may need cluster credentials)"

# ── Step 6: Create policy ─────────────────────────────────────────
echo "[6/8] Creating wadjet-eye policy..."
vault policy write wadjet-eye - <<'POLICY'
# Wadjet-Eye Backend Service Policy
path "secret/data/wadjet-eye/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/wadjet-eye/*" {
  capabilities = ["read", "list"]
}
path "secret/data/wadjet-eye/ai-keys" {
  capabilities = ["read"]
}
path "secret/data/wadjet-eye/db" {
  capabilities = ["read"]
}
path "secret/data/wadjet-eye/jwt" {
  capabilities = ["read"]
}
path "secret/data/wadjet-eye/integrations" {
  capabilities = ["read"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
POLICY
echo "  ✓ Policy created"

# ── Step 7: Create AppRole ────────────────────────────────────────
echo "[7/8] Creating wadjet-eye AppRole..."
vault write auth/approle/role/wadjet-eye \
  token_ttl=1h \
  token_max_ttl=4h \
  token_policies="wadjet-eye" \
  secret_id_ttl=0 \
  secret_id_num_uses=0 \
  bind_secret_id=true

ROLE_ID=$(vault read -field=role_id auth/approle/role/wadjet-eye/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/wadjet-eye/secret-id)

echo "  ✓ AppRole created"
echo ""
echo "  VAULT_ROLE_ID:   $ROLE_ID"
echo "  VAULT_SECRET_ID: $SECRET_ID"
echo ""
echo "  Add these to your .env or K8s secrets!"

# ── Step 8: Seed placeholder secrets ────────────────────────────
echo "[8/8] Seeding secret placeholders..."

vault kv put secret/wadjet-eye/ai-keys \
  OPENAI_API_KEY="REPLACE_WITH_REAL_KEY" \
  CLAUDE_API_KEY="REPLACE_WITH_REAL_KEY" \
  GEMINI_API_KEY="REPLACE_WITH_REAL_KEY" \
  DEEPSEEK_API_KEY="REPLACE_WITH_REAL_KEY"

vault kv put secret/wadjet-eye/db \
  SUPABASE_URL="REPLACE_WITH_SUPABASE_URL" \
  SUPABASE_SERVICE_KEY="REPLACE_WITH_SERVICE_KEY" \
  SUPABASE_ANON_KEY="REPLACE_WITH_ANON_KEY" \
  NEO4J_URI="bolt://neo4j:7687" \
  NEO4J_USERNAME="neo4j" \
  NEO4J_PASSWORD="REPLACE_WITH_STRONG_PASSWORD" \
  REDIS_URL="redis://redis:6379" \
  REDIS_PASSWORD="REPLACE_WITH_REDIS_PASSWORD"

vault kv put secret/wadjet-eye/jwt \
  JWT_SECRET="REPLACE_WITH_64CHAR_RANDOM_SECRET" \
  CSRF_SECRET="REPLACE_WITH_64CHAR_RANDOM_SECRET" \
  COOKIE_SECRET="REPLACE_WITH_64CHAR_RANDOM_SECRET"

vault kv put secret/wadjet-eye/integrations \
  VIRUSTOTAL_API_KEY="REPLACE" \
  ABUSEIPDB_API_KEY="REPLACE" \
  SHODAN_API_KEY="REPLACE" \
  OTX_API_KEY="REPLACE" \
  SPLUNK_HEC_TOKEN="REPLACE" \
  SENTINEL_PRIMARY_KEY="REPLACE" \
  PASTEBIN_API_KEY="REPLACE"

vault kv put secret/wadjet-eye/kafka \
  KAFKA_SASL_USERNAME="wadjet-eye" \
  KAFKA_SASL_PASSWORD="REPLACE_WITH_KAFKA_PASSWORD"

echo ""
echo "══════════════════════════════════════════"
echo " Vault bootstrap COMPLETE"
echo " Update all REPLACE_WITH_* values!"
echo "══════════════════════════════════════════"
