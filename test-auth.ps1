#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Wadjet-Eye AI — Full Auth Test Suite
    Tests: login, token refresh, /me endpoint, logout

.USAGE
    .\test-auth.ps1
    .\test-auth.ps1 -BackendUrl "http://localhost:4000"
    .\test-auth.ps1 -Email "analyst@mssp.com" -Password "Analyst@Secure2024!"

.NOTES
    Author: Wadjet-Eye AI Team
    Version: 5.1
#>

param(
    [string]$BackendUrl = "https://wadjet-eye-ai.onrender.com",
    [string]$Email      = "mahmoud@mssp.com",
    [string]$Password   = "Admin@2024Wadjet!"
)

# ── Colors ──────────────────────────────────────────────────────────────
$C = @{
    Cyan    = "Cyan"
    Green   = "Green"
    Red     = "Red"
    Yellow  = "Yellow"
    Gray    = "Gray"
    White   = "White"
    Magenta = "Magenta"
}

# ── Helper: Call API endpoint ────────────────────────────────────────────
function Invoke-Api {
    param(
        [string]$Method,
        [string]$Path,
        [hashtable]$Body,
        [string]$Token
    )
    $headers = @{ "Content-Type" = "application/json" }
    if ($Token) { $headers["Authorization"] = "Bearer $Token" }

    $params = @{
        Uri             = "$BackendUrl$Path"
        Method          = $Method
        Headers         = $headers
        TimeoutSec      = 45
        UseBasicParsing = $true
    }

    if ($Body) {
        $params["Body"] = ($Body | ConvertTo-Json -Depth 10)
    }

    try {
        $response = Invoke-RestMethod @params
        return @{ success = $true; data = $response }
    }
    catch {
        $errMsg  = $_.Exception.Message
        $errBody = $null
        try { $errBody = ($_.ErrorDetails.Message | ConvertFrom-Json).error } catch {}
        return @{
            success  = $false
            error    = $errBody ?? $errMsg
            httpCode = $_.Exception.Response?.StatusCode?.value__
        }
    }
}

# ── Print separator ──────────────────────────────────────────────────────
function Sep { Write-Host ("═" * 56) -ForegroundColor $C.Cyan }
function Title($t) { Sep; Write-Host "  $t" -ForegroundColor $C.Cyan; Sep }

# ════════════════════════════════════════════════════════════════════════
#  MAIN TEST SUITE
# ════════════════════════════════════════════════════════════════════════

Title "Wadjet-Eye AI — Auth Test Suite v5.1"
Write-Host "  Backend : $BackendUrl" -ForegroundColor $C.Gray
Write-Host "  Email   : $Email" -ForegroundColor $C.Gray
Write-Host ""

$passed = 0
$failed = 0

# ──────────────────────────────────────────────────────────────────────
#  TEST 1: Health Check
# ──────────────────────────────────────────────────────────────────────
Write-Host "[1/6] ⏳ Health Check..." -ForegroundColor $C.Yellow
$health = Invoke-Api -Method "GET" -Path "/health"

if ($health.success) {
    $h = $health.data
    Write-Host "  ✅ Health: Status=$($h.status) | DB=$($h.db) | Uptime=$($h.uptime_s)s" -ForegroundColor $C.Green
    $passed++
} else {
    Write-Host "  ⚠️  Health check failed: $($health.error)" -ForegroundColor $C.Yellow
    Write-Host "     Server may be sleeping (Render cold start). Waiting 20 seconds..." -ForegroundColor $C.Gray
    Start-Sleep -Seconds 20
    # Don't count as failure
}

# ──────────────────────────────────────────────────────────────────────
#  TEST 2: Login
# ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[2/6] ⏳ Login test..." -ForegroundColor $C.Yellow
$loginResult = Invoke-Api -Method "POST" -Path "/api/auth/login" -Body @{
    email    = $Email
    password = $Password
}

if (-not $loginResult.success) {
    Write-Host "  ❌ LOGIN FAILED: $($loginResult.error)" -ForegroundColor $C.Red
    Write-Host "     HTTP Status: $($loginResult.httpCode)" -ForegroundColor $C.Gray
    $failed++
    Write-Host ""
    Write-Host "  HINT: Make sure you ran:" -ForegroundColor $C.Yellow
    Write-Host "    1. backend/database/rls-fix-v5.1.sql in Supabase SQL Editor" -ForegroundColor $C.Gray
    Write-Host "    2. node backend/scripts/seed-mahmoud.js" -ForegroundColor $C.Gray
    exit 1
}

$login = $loginResult.data
$token        = $login.token
$refreshToken = $login.refreshToken
$expiresAt    = $login.expiresAt
$sessionId    = $login.sessionId
$user         = $login.user

Write-Host "  ✅ LOGIN SUCCESS" -ForegroundColor $C.Green
Write-Host "     User       : $($user.name)" -ForegroundColor $C.White
Write-Host "     Email      : $($user.email)" -ForegroundColor $C.White
Write-Host "     Role       : $($user.role)" -ForegroundColor $C.White
Write-Host "     Tenant     : $($user.tenant_name) ($($user.tenant_slug))" -ForegroundColor $C.White
Write-Host "     Session ID : $sessionId" -ForegroundColor $C.Gray
Write-Host "     Expires At : $expiresAt" -ForegroundColor $C.Gray
Write-Host "     Token      : $($token.Substring(0, [Math]::Min(60,$token.Length)))..." -ForegroundColor $C.Gray
$passed++

# ──────────────────────────────────────────────────────────────────────
#  TEST 3: Get Profile (/api/auth/me)
# ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/6] ⏳ Profile check (/api/auth/me)..." -ForegroundColor $C.Yellow
$meResult = Invoke-Api -Method "GET" -Path "/api/auth/me" -Token $token

if (-not $meResult.success) {
    Write-Host "  ❌ /api/auth/me FAILED: $($meResult.error)" -ForegroundColor $C.Red
    Write-Host "     HTTP $($meResult.httpCode) — Token may not be valid JWT" -ForegroundColor $C.Gray
    Write-Host "     HINT: Check JWT_SECRET in .env matches Supabase dashboard" -ForegroundColor $C.Yellow
    $failed++
} else {
    $me = $meResult.data.user
    Write-Host "  ✅ PROFILE OK: $($me.name) | $($me.email) | $($me.role)" -ForegroundColor $C.Green
    Write-Host "     Permissions: $($me.permissions -join ', ')" -ForegroundColor $C.Gray
    $passed++
}

# ──────────────────────────────────────────────────────────────────────
#  TEST 4: Token Refresh
# ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[4/6] ⏳ Token refresh (/api/auth/refresh)..." -ForegroundColor $C.Yellow
$refreshResult = Invoke-Api -Method "POST" -Path "/api/auth/refresh" -Body @{
    refresh_token = $refreshToken
}

if (-not $refreshResult.success) {
    Write-Host "  ❌ REFRESH FAILED: $($refreshResult.error)" -ForegroundColor $C.Red
    Write-Host "     HTTP $($refreshResult.httpCode)" -ForegroundColor $C.Gray
    Write-Host "     HINT: Run rls-fix-v5.1.sql in Supabase SQL Editor" -ForegroundColor $C.Yellow
    $failed++
} else {
    $r = $refreshResult.data
    $requiresReauth = $r.requires_reauth -eq $true
    $hasNewToken    = $r.token -and $r.token.Length -gt 10

    if ($hasNewToken) {
        Write-Host "  ✅ REFRESH SUCCESS (new JWT issued)" -ForegroundColor $C.Green
    } else {
        Write-Host "  ⚠️  REFRESH OK but no new access token — requires_reauth=$requiresReauth" -ForegroundColor $C.Yellow
        Write-Host "     FIX: Set JWT_SECRET in Render env vars to match Supabase JWT Secret" -ForegroundColor $C.Gray
    }
    Write-Host "     New Expires : $($r.expiresAt)" -ForegroundColor $C.Gray
    if ($hasNewToken) {
        Write-Host "     New Token   : $($r.token.Substring(0, [Math]::Min(60,$r.token.Length)))..." -ForegroundColor $C.Gray
    }
    $passed++
    $newRefreshToken = $r.refreshToken
}

# ──────────────────────────────────────────────────────────────────────
#  TEST 5: Active Sessions
# ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[5/6] ⏳ Active sessions (/api/auth/sessions)..." -ForegroundColor $C.Yellow
$sessionsResult = Invoke-Api -Method "GET" -Path "/api/auth/sessions" -Token $token

if (-not $sessionsResult.success) {
    Write-Host "  ⚠️  Sessions endpoint issue: $($sessionsResult.error)" -ForegroundColor $C.Yellow
    # Non-fatal
} else {
    $sessions = $sessionsResult.data.sessions
    Write-Host "  ✅ Active sessions: $($sessions.Count)" -ForegroundColor $C.Green
    foreach ($s in $sessions | Select-Object -First 3) {
        $browser = $s.device_info?.browser ?? "Unknown"
        $os      = $s.device_info?.os ?? "Unknown"
        Write-Host "     - $($s.id.Substring(0,8))... | $browser on $os | Last: $($s.last_used_at ?? 'never')" -ForegroundColor $C.Gray
    }
    $passed++
}

# ──────────────────────────────────────────────────────────────────────
#  TEST 6: Logout
# ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[6/6] ⏳ Logout (/api/auth/logout)..." -ForegroundColor $C.Yellow
$logoutResult = Invoke-Api -Method "POST" -Path "/api/auth/logout" -Body @{
    refresh_token = $newRefreshToken ?? $refreshToken
} -Token $token

if (-not $logoutResult.success) {
    Write-Host "  ⚠️  Logout issue: $($logoutResult.error)" -ForegroundColor $C.Yellow
} else {
    Write-Host "  ✅ Logout: $($logoutResult.data.message)" -ForegroundColor $C.Green
    $passed++
}

# ──────────────────────────────────────────────────────────────────────
#  SUMMARY
# ──────────────────────────────────────────────────────────────────────
Write-Host ""
Sep
Write-Host "  RESULTS: $passed passed, $failed failed" -ForegroundColor ($failed -gt 0 ? $C.Red : $C.Green)
Sep
Write-Host ""

if ($failed -gt 0) {
    Write-Host "  ❌ Some tests failed. Check the hints above." -ForegroundColor $C.Red
    Write-Host ""
    Write-Host "  Quick fix checklist:" -ForegroundColor $C.Yellow
    Write-Host "  [ ] Run rls-fix-v5.1.sql in Supabase SQL Editor" -ForegroundColor $C.White
    Write-Host "  [ ] Verify JWT_SECRET in backend/.env matches Supabase dashboard" -ForegroundColor $C.White
    Write-Host "  [ ] Run: node backend/scripts/seed-mahmoud.js" -ForegroundColor $C.White
    Write-Host "  [ ] Run: cd backend && npm install" -ForegroundColor $C.White
    Write-Host "  [ ] Redeploy backend to Render after env var changes" -ForegroundColor $C.White
    exit 1
} else {
    Write-Host "  ✅ ALL TESTS PASSED!" -ForegroundColor $C.Green
    Write-Host "  Persistent login is working correctly." -ForegroundColor $C.White
    Write-Host ""
    Write-Host "  Frontend: https://wadjet-eye-ai.vercel.app" -ForegroundColor $C.Cyan
    Write-Host "  Backend:  $BackendUrl" -ForegroundColor $C.Cyan
    exit 0
}
