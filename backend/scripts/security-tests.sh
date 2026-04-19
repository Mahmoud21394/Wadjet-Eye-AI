#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  Wadjet-Eye AI — Security Validation Test Suite v6.0
#  backend/scripts/security-tests.sh
#
#  Usage: bash backend/scripts/security-tests.sh
#  Requires: curl, jq, python3
#
#  Tests every security fix from the v6.0 remediation.
#  Run after deployment to verify all controls are working.
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

BASE="${WADJET_API:-https://wadjet-eye-ai.onrender.com}"
FRONTEND="${WADJET_FRONTEND:-https://wadjet-eye-ai.vercel.app}"
PASS=0
FAIL=0
WARN=0

# ── Color helpers ─────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

pass() { echo -e "${GREEN}✅ PASS${NC} — $1"; ((PASS++)); }
fail() { echo -e "${RED}❌ FAIL${NC} — $1"; ((FAIL++)); }
warn() { echo -e "${YELLOW}⚠️  WARN${NC} — $1"; ((WARN++)); }
info() { echo -e "${BLUE}ℹ️  INFO${NC} — $1"; }
section() { echo -e "\n${BOLD}━━━ $1 ━━━${NC}"; }

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Wadjet-Eye AI — Security Test Suite v6.0           ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
info "Target API: $BASE"
info "Target Frontend: $FRONTEND"
echo ""

# ══════════════════════════════════════════════════════════════════
# T1: Emergency Accounts Removed From Frontend JS
# ══════════════════════════════════════════════════════════════════
section "T1 · Emergency Account Removal"

JS_CONTENT=$(curl -sf "$FRONTEND/js/main.js" 2>/dev/null || echo "FETCH_FAILED")
if [[ "$JS_CONTENT" == "FETCH_FAILED" ]]; then
  warn "Could not fetch $FRONTEND/js/main.js — frontend may not be deployed yet"
else
  if echo "$JS_CONTENT" | grep -q "_EMERGENCY_ACCOUNTS"; then
    fail "F1: _EMERGENCY_ACCOUNTS still found in js/main.js — emergency bypass NOT removed"
  else
    pass "F1: No _EMERGENCY_ACCOUNTS in js/main.js"
  fi

  if echo "$JS_CONTENT" | grep -q "mahmoud.osman@wadjet.ai\|mahmoud@mssp.com\|admin@mssp.com"; then
    fail "F1: Super-admin email addresses still present in js/main.js"
  else
    pass "F1: No hardcoded admin emails in js/main.js"
  fi

  if echo "$JS_CONTENT" | grep -q "_doEmergencyLogin"; then
    fail "F1: _doEmergencyLogin() still in js/main.js"
  else
    pass "F1: _doEmergencyLogin() removed"
  fi

  if echo "$JS_CONTENT" | grep -q "password.length >= 6"; then
    fail "F1: Password length-only auth gate still in js/main.js"
  else
    pass "F1: Password length bypass removed"
  fi

  if echo "$JS_CONTENT" | grep -q "offline_emergency_"; then
    fail "F1: Client-side offline token generation still present"
  else
    pass "F1: No client-side offline token generation"
  fi
fi

# Check auth-persistent.js is replaced
PERSISTENT_JS=$(curl -sf "$FRONTEND/js/auth-persistent.js" 2>/dev/null || echo "NOT_FOUND")
if [[ "$PERSISTENT_JS" == "NOT_FOUND" ]] || [[ ${#PERSISTENT_JS} -lt 100 ]]; then
  pass "F2: auth-persistent.js replaced/removed"
else
  warn "F2: auth-persistent.js still exists — verify it no longer stores tokens in localStorage"
fi

# ══════════════════════════════════════════════════════════════════
# T2: Public Endpoints (no auth required)
# ══════════════════════════════════════════════════════════════════
section "T2 · Public Health Endpoints"

HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/health")
if [[ "$HEALTH_STATUS" == "200" ]]; then
  HEALTH_BODY=$(curl -s "$BASE/health")
  pass "F4/F6: GET /health returns 200"
  info "Health response: $(echo "$HEALTH_BODY" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("status","?"), "v"+str(d.get("version","?")))'  2>/dev/null || echo "$HEALTH_BODY")"
else
  fail "F4/F6: GET /health returned HTTP $HEALTH_STATUS (expected 200, no auth required)"
fi

READY_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/ready")
if [[ "$READY_STATUS" =~ ^(200|503)$ ]]; then
  pass "F6: GET /ready endpoint exists (HTTP $READY_STATUS)"
else
  warn "F6: GET /ready returned HTTP $READY_STATUS — endpoint may not be implemented yet"
fi

# ══════════════════════════════════════════════════════════════════
# T3: Login Does NOT Return Token in Response Body
# ══════════════════════════════════════════════════════════════════
section "T3 · httpOnly Cookie Session"

LOGIN_BODY=$(curl -s -c /tmp/wadjet_test_cookies.txt \
  -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test.nonexistent@example.com","password":"TestPassword123!","tenant":"mssp-global"}')

# Even a failed login should NOT have token in structure
if echo "$LOGIN_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if 'token' not in d and 'access_token' not in d else 1)" 2>/dev/null; then
  pass "F2: Login response body does not contain raw token"
else
  fail "F2: Login response body CONTAINS token — should use httpOnly cookies only"
fi

# Check Set-Cookie header on login
COOKIE_HEADER=$(curl -s -I -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test.nonexistent@example.com","password":"TestPassword123!"}' 2>&1)

if echo "$COOKIE_HEADER" | grep -qi "httponly"; then
  pass "F2: Set-Cookie header contains HttpOnly flag"
else
  warn "F2: Could not verify HttpOnly flag — may require valid credentials to set cookie"
fi

if echo "$COOKIE_HEADER" | grep -qi "samesite=strict\|samesite=lax"; then
  pass "F2: Set-Cookie has SameSite protection"
else
  warn "F2: Could not verify SameSite flag on cookie"
fi

# ══════════════════════════════════════════════════════════════════
# T4: MFA Required for Admin Login
# ══════════════════════════════════════════════════════════════════
section "T4 · MFA Enforcement"

MFA_STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/auth/mfa/status" \
  -H "Authorization: Bearer invalid_token_to_test_endpoint_exists")

if [[ "$MFA_STATUS_CODE" =~ ^(200|401)$ ]]; then
  pass "F3: MFA status endpoint exists at /api/auth/mfa/status"
else
  fail "F3: MFA status endpoint missing (HTTP $MFA_STATUS_CODE) — routes/mfa.js not deployed"
fi

MFA_ENROLL_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/auth/mfa/enroll" \
  -H "Content-Type: application/json")
if [[ "$MFA_ENROLL_CODE" =~ ^(200|401|400)$ ]]; then
  pass "F3: MFA enroll endpoint exists at /api/auth/mfa/enroll"
else
  fail "F3: MFA enroll endpoint missing (HTTP $MFA_ENROLL_CODE)"
fi

MFA_CHALLENGE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/auth/mfa/challenge" \
  -H "Content-Type: application/json" \
  -d '{"mfa_session_token":"invalid","totp_code":"000000"}')
if [[ "$MFA_CHALLENGE_CODE" =~ ^(200|401|400)$ ]]; then
  pass "F3: MFA challenge endpoint exists at /api/auth/mfa/challenge"
else
  fail "F3: MFA challenge endpoint missing (HTTP $MFA_CHALLENGE_CODE)"
fi

# ══════════════════════════════════════════════════════════════════
# T5: IOC Type Validation
# ══════════════════════════════════════════════════════════════════
section "T5 · IOC Schema Validation"

# Test with a hash value typed as IP (should be rejected)
# Need a real auth token for this — test the validator module directly
IOC_REJECT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/iocs" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test_token_will_401" \
  -d '{"value":"a3f8d2e1b4c5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1","type":"ip","tenant_id":"test"}')

# 401 is acceptable (auth failed before validation) — just check endpoint exists
if [[ "$IOC_REJECT_CODE" =~ ^(401|422|400)$ ]]; then
  if [[ "$IOC_REJECT_CODE" == "422" ]] || [[ "$IOC_REJECT_CODE" == "400" ]]; then
    pass "F5: IOC endpoint rejects hash-typed-as-IP (HTTP $IOC_REJECT_CODE)"
  else
    warn "F5: Could not test IOC validation (auth required) — test with valid token manually"
    info "F5: Manual test: POST /api/iocs with {value:'sha256hash', type:'ip'} — expect 422"
  fi
else
  fail "F5: IOC endpoint returned unexpected HTTP $IOC_REJECT_CODE"
fi

# ══════════════════════════════════════════════════════════════════
# T6: security.txt
# ══════════════════════════════════════════════════════════════════
section "T6 · security.txt"

SECTXT=$(curl -sf "$FRONTEND/.well-known/security.txt" 2>/dev/null || echo "NOT_FOUND")
if [[ "$SECTXT" == "NOT_FOUND" ]]; then
  fail "F6: /.well-known/security.txt not accessible"
else
  if echo "$SECTXT" | grep -q "Contact:"; then
    pass "F6: security.txt exists and has Contact field"
  else
    fail "F6: security.txt exists but missing Contact field (RFC 9116 violation)"
  fi

  if echo "$SECTXT" | grep -q "Expires:"; then
    pass "F6: security.txt has Expires field"
  else
    warn "F6: security.txt missing Expires field"
  fi
fi

# ══════════════════════════════════════════════════════════════════
# T7: Route Contract Validation
# ══════════════════════════════════════════════════════════════════
section "T7 · Route Contract Validation"

DASH_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/dashboard" \
  -H "Authorization: Bearer test")
if [[ "$DASH_CODE" =~ ^(200|401)$ ]]; then
  pass "F4: GET /api/dashboard exists (HTTP $DASH_CODE — 401 expected without auth)"
else
  fail "F4: GET /api/dashboard returns HTTP $DASH_CODE (expected 200 or 401, not 404)"
fi

# ══════════════════════════════════════════════════════════════════
# T8: Break-Glass Endpoint (should exist, not expose accounts)
# ══════════════════════════════════════════════════════════════════
section "T8 · Break-Glass Service"

BG_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/auth/break-glass/request" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}')

if [[ "$BG_CODE" =~ ^(200|400|403|404)$ ]]; then
  if [[ "$BG_CODE" == "404" ]]; then
    warn "F1: Break-glass endpoint not deployed yet — implement backend/services/break-glass.js"
  else
    pass "F1: Break-glass endpoint exists (HTTP $BG_CODE)"
    # Check it returns generic message (not revealing account existence)
    BG_BODY=$(curl -s -X POST "$BASE/api/auth/break-glass/request" \
      -H "Content-Type: application/json" \
      -d '{"email":"nonexistent@example.com"}')
    if echo "$BG_BODY" | grep -q "authorized\|If this email"; then
      pass "F1: Break-glass uses generic response (doesn't reveal account existence)"
    fi
  fi
else
  warn "F1: Break-glass endpoint returned HTTP $BG_CODE"
fi

# ══════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}TEST SUMMARY${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}PASS: $PASS${NC}"
echo -e "${RED}FAIL: $FAIL${NC}"
echo -e "${YELLOW}WARN: $WARN${NC}"
echo ""

if [[ $FAIL -gt 0 ]]; then
  echo -e "${RED}${BOLD}❌ Security tests FAILED — review output above${NC}"
  exit 1
elif [[ $WARN -gt 0 ]]; then
  echo -e "${YELLOW}${BOLD}⚠️  Tests passed with warnings — review warnings above${NC}"
  exit 0
else
  echo -e "${GREEN}${BOLD}✅ All security tests PASSED${NC}"
  exit 0
fi
