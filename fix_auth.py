#!/usr/bin/env python3
"""
Wadjet-Eye AI — Auth v7.4 Fix Script
Applies all identified fixes to backend auth files.
"""
import re, sys, os

def patch_file(filepath, patches):
    """Apply a list of (old, new, description) patches to a file."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    applied = []
    skipped = []
    for old, new, desc in patches:
        if old in content:
            content = content.replace(old, new, 1)
            applied.append(desc)
        else:
            skipped.append(desc)
    
    with open(filepath, 'w') as f:
        f.write(content)
    
    return applied, skipped

# ═══════════════════════════════════════════════════════════════════
# PATCH 1: backend/config/supabase.js
# ═══════════════════════════════════════════════════════════════════
supabase_patches = [
    # Fix: version bump
    (
        'Wadjet-Eye AI — Supabase Client v7.0 (Timeout Root-Cause Fix)',
        'Wadjet-Eye AI — Supabase Client v7.4 (Timeout Root-Cause Fix)',
        'supabase.js: version bump to v7.4'
    ),
    # Fix: isAbortError must also catch AUTH_SERVICE_UNAVAILABLE + SERVER_ERROR codes
    (
        "    msg.includes('fetch timeout exceeded')           ||  // our custom _*FetchWithTimeout messages\n"
        "    msg.includes('login fetch timeout')              ||\n"
        "    msg.includes('auth fetch timeout')               ||\n"
        "    msg.includes('db fetch timeout')                 ||\n"
        "    msg.includes('ingestion fetch timeout')          ||\n"
        "    msg.includes('timeout of')                       ||  // axios: \"timeout of Xms exceeded\"\n"
        "    msg.includes('network error')                    ||  // axios network errors\n"
        "    msg.includes('connect etimedout')\n"
        "  );\n"
        "}",
        "    msg.includes('fetch timeout exceeded')           ||  // our custom _*FetchWithTimeout messages\n"
        "    msg.includes('login fetch timeout')              ||\n"
        "    msg.includes('auth fetch timeout')               ||\n"
        "    msg.includes('db fetch timeout')                 ||\n"
        "    msg.includes('ingestion fetch timeout')          ||\n"
        "    msg.includes('timeout of')                       ||  // axios: \"timeout of Xms exceeded\"\n"
        "    msg.includes('network error')                    ||  // axios network errors\n"
        "    msg.includes('connect etimedout')                ||\n"
        "    // v7.4 FIX: AUTH_SERVICE_UNAVAILABLE + SERVER_ERROR from signInWithPasswordDirect\n"
        "    err.code === 'AUTH_SERVICE_UNAVAILABLE'          ||\n"
        "    err.code === 'SERVER_ERROR'                      ||\n"
        "    msg.includes('auth_service_unavailable')         ||\n"
        "    msg.includes('login service unavailable')\n"
        "  );\n"
        "}",
        'supabase.js: isAbortError catches AUTH_SERVICE_UNAVAILABLE + SERVER_ERROR'
    ),
    # Fix: export LOGIN_DIRECT_RETRY_DELAY
    (
        "// Export constants for audit checks\n"
        "module.exports.LOGIN_DIRECT_TIMEOUT_MS  = LOGIN_DIRECT_TIMEOUT_MS;\n"
        "module.exports.LOGIN_DIRECT_MAX_RETRIES = LOGIN_DIRECT_MAX_RETRIES;\n"
        "module.exports.signInWithPasswordDirect = signInWithPasswordDirect;",
        "// Export constants for audit checks\n"
        "module.exports.LOGIN_DIRECT_TIMEOUT_MS  = LOGIN_DIRECT_TIMEOUT_MS;\n"
        "module.exports.LOGIN_DIRECT_MAX_RETRIES = LOGIN_DIRECT_MAX_RETRIES;\n"
        "module.exports.LOGIN_DIRECT_RETRY_DELAY = LOGIN_DIRECT_RETRY_DELAY;\n"
        "module.exports.signInWithPasswordDirect = signInWithPasswordDirect;",
        'supabase.js: export LOGIN_DIRECT_RETRY_DELAY'
    ),
]

# ═══════════════════════════════════════════════════════════════════
# PATCH 2: backend/routes/auth.js
# ═══════════════════════════════════════════════════════════════════
auth_patches = [
    # Fix: version header
    (
        'Enterprise Auth Routes v7.0',
        'Enterprise Auth Routes v7.4',
        'auth.js: version bump to v7.4'
    ),
    # Fix: Add SERVER_ERROR to 503 trigger
    (
        "    // v7.3 FIX: Check for timeout/abort/network errors BEFORE credential checks.\n"
        "    // signInWithPasswordDirect returns these in the error object with matching names/codes.\n"
        "    if (isAbortError(loginError) || isNetworkError(loginError) ||\n"
        "        loginError.code === 'ECONNABORTED' || loginError.code === 'ETIMEDOUT' ||\n"
        "        loginError.code === 'ECONNREFUSED'  || loginError.code === 'ECONNRESET'  ||\n"
        "        loginError.code === 'AUTH_SERVICE_UNAVAILABLE') {",
        "    // v7.4 FIX: Check for timeout/abort/network/server errors BEFORE credential checks.\n"
        "    // signInWithPasswordDirect returns these in the error object with matching names/codes.\n"
        "    // isAbortError() now catches AUTH_SERVICE_UNAVAILABLE + SERVER_ERROR (v7.4).\n"
        "    if (isAbortError(loginError) || isNetworkError(loginError) ||\n"
        "        loginError.code === 'ECONNABORTED' || loginError.code === 'ETIMEDOUT' ||\n"
        "        loginError.code === 'ECONNREFUSED'  || loginError.code === 'ECONNRESET'  ||\n"
        "        loginError.code === 'AUTH_SERVICE_UNAVAILABLE' ||\n"
        "        loginError.code === 'SERVER_ERROR') {",
        'auth.js: SERVER_ERROR added to 503 trigger'
    ),
    # Fix: Replace generic 401 fallback with smart 503/401 split
    (
        "    // Generic 401 for any other Supabase auth failure\n"
        "    return res.status(401).json({\n"
        "      error: 'Invalid email or password',\n"
        "      code:  'INVALID_CREDENTIALS',\n"
        "      _supabaseMsg: process.env.NODE_ENV !== 'production' ? loginError.message : undefined,\n"
        "    });\n"
        "  }",
        "    // v7.4 FIX: Detect Supabase 5xx / unexpected errors that should be 503, not 401.\n"
        "    // Only return 401 INVALID_CREDENTIALS when we are confident this is a real auth failure.\n"
        "    const isDefiniteAuthError =\n"
        "      errMsg.includes('invalid') ||\n"
        "      errMsg.includes('wrong')   ||\n"
        "      errMsg.includes('not found') ||\n"
        "      errMsg.includes('not confirmed') ||\n"
        "      errMsg.includes('credentials') ||\n"
        "      errCode === 400 || errCode === 401;\n"
        "\n"
        "    if (!isDefiniteAuthError) {\n"
        "      // Unknown Supabase error — safer to return 503 than a misleading 401\n"
        "      const elapsed503 = Date.now() - loginStart;\n"
        "      console.error(`[auth:login:503-fallback] Unknown loginError: \"${loginError.message}\" ` +\n"
        "        `code=${loginError.code} status=${loginError.status} elapsed=${elapsed503}ms`);\n"
        "      logActivity(null, null, 'LOGIN_FAILED', req, {\n"
        "        email, success: false,\n"
        "        failure_reason: `UnknownError: ${loginError.message}`,\n"
        "      }).catch(() => {});\n"
        "      return res.status(503).json({\n"
        "        error:   'Authentication service temporarily unavailable. Please try again in a few seconds.',\n"
        "        code:    'AUTH_SERVICE_UNAVAILABLE',\n"
        "        retryIn: 5,\n"
        "      });\n"
        "    }\n"
        "\n"
        "    // Generic 401 for definitive credential failures only\n"
        "    return res.status(401).json({\n"
        "      error: 'Invalid email or password',\n"
        "      code:  'INVALID_CREDENTIALS',\n"
        "      _supabaseMsg: process.env.NODE_ENV !== 'production' ? loginError.message : undefined,\n"
        "    });\n"
        "  }",
        'auth.js: Generic 401 replaced with smart 503/401 split'
    ),
    # Fix: Add code field to refresh 401 response
    (
        "    await logActivity(null, null, 'TOKEN_REFRESH_FAILED', req, {\n"
        "      success: false,\n"
        "      failure_reason: err.message,\n"
        "    });\n"
        "    return res.status(401).json({ error: err.message });",
        "    // v7.4 FIX: Structured 401 with code field for frontend to distinguish error types\n"
        "    const refreshErrCode = err.message?.includes('expired')\n"
        "      ? 'REFRESH_TOKEN_EXPIRED'\n"
        "      : err.message?.includes('suspended')\n"
        "      ? 'ACCOUNT_SUSPENDED'\n"
        "      : err.message?.includes('Session validation')\n"
        "      ? 'SESSION_VALIDATION_UNAVAILABLE'\n"
        "      : 'INVALID_REFRESH_TOKEN';\n"
        "\n"
        "    await logActivity(null, null, 'TOKEN_REFRESH_FAILED', req, {\n"
        "      success: false,\n"
        "      failure_reason: err.message,\n"
        "    });\n"
        "    return res.status(401).json({\n"
        "      error: err.message,\n"
        "      code:  refreshErrCode,\n"
        "    });",
        'auth.js: Refresh 401 now has structured code field'
    ),
    # Fix: diagnostics version
    (
        "    version: '7.3',",
        "    version: '7.4',",
        'auth.js: diagnostics version bump'
    ),
]

# ═══════════════════════════════════════════════════════════════════
# PATCH 3: backend/middleware/auth.js
# ═══════════════════════════════════════════════════════════════════
middleware_patches = [
    # Fix: Check isAbortError on authError (returned in field, not thrown)
    (
        "    if (authError) {\n"
        "      const isExpired = authError.message?.toLowerCase().includes('expired') ||\n"
        "                        authError.message?.toLowerCase().includes('jwt expired');\n"
        "      const code = isExpired ? 'EXPIRED_TOKEN' : 'INVALID_TOKEN';\n"
        "      console.warn(`[Auth] 401 ${code} src=${source} reqId=${reqId} ${req.method} ${req.path}: ${authError.message}`);\n"
        "      return res.status(401).json({\n"
        "        error: isExpired ? 'Token has expired. Please refresh your session.' : 'Invalid token. Please log in again.',\n"
        "        code,\n"
        "        message: authError.message,\n"
        "      });\n"
        "    }",
        "    if (authError) {\n"
        "      // v7.4 FIX: If getUser() returns AbortError in the error field (not thrown),\n"
        "      // return 503 AUTH_SERVICE_UNAVAILABLE — NOT 401 INVALID_TOKEN.\n"
        "      if (isAbortError(authError) || isTimeoutError(authError)) {\n"
        "        console.error(`[Auth] 503 AUTH_ABORT src=${source} reqId=${reqId} ${req.method} ${req.path}: ${authError.message}`);\n"
        "        clearTimeout(_verifyTimeoutId);\n"
        "        return res.status(503).json({\n"
        "          error: 'Authentication service temporarily unavailable. Please retry in a moment.',\n"
        "          code:  'AUTH_SERVICE_UNAVAILABLE',\n"
        "          retryAfter: 5,\n"
        "        });\n"
        "      }\n"
        "      const isExpired = authError.message?.toLowerCase().includes('expired') ||\n"
        "                        authError.message?.toLowerCase().includes('jwt expired');\n"
        "      const code = isExpired ? 'EXPIRED_TOKEN' : 'INVALID_TOKEN';\n"
        "      console.warn(`[Auth] 401 ${code} src=${source} reqId=${reqId} ${req.method} ${req.path}: ${authError.message}`);\n"
        "      return res.status(401).json({\n"
        "        error: isExpired ? 'Token has expired. Please refresh your session.' : 'Invalid token. Please log in again.',\n"
        "        code,\n"
        "        message: authError.message,\n"
        "      });\n"
        "    }",
        'auth middleware: isAbortError check on authError field before 401 INVALID_TOKEN'
    ),
    # Fix: version in header comment
    (
        'Wadjet-Eye AI — Secure Auth Middleware v6.0',
        'Wadjet-Eye AI — Secure Auth Middleware v6.1 (v7.4 abort fix)',
        'auth middleware: version bump'
    ),
]

# ═══════════════════════════════════════════════════════════════════
# PATCH 4: js/login-secure-patch.js
# ═══════════════════════════════════════════════════════════════════
frontend_patches = [
    # Fix: version header
    (
        'Wadjet-Eye AI — Secure Login Patch v6.1',
        'Wadjet-Eye AI — Secure Login Patch v6.2 (v7.4 retryIn fix)',
        'login-secure-patch.js: version bump'
    ),
    # Fix: Use retryIn from server response, reset _autoRetryCount on form submit
    (
        "  } catch (err) {\n"
        "    _setBtnLoading(btn, false);\n"
        "\n"
        "    const msg = err.message || 'Login failed';\n"
        "    const display = _mapLoginError(msg);\n"
        "\n"
        "    _showLoginError(errEl, display);\n"
        "    console.warn('[SecureLogin] Authentication failed:', msg);\n"
        "\n"
        "    // ── Auto-retry for 503 AUTH_SERVICE_UNAVAILABLE ────────────────────────\n"
        "    // v7.3: The backend now does 3 internal retries via axios (12s each).\n"
        "    // By the time we get a 503, the backend has already exhausted its retries.\n"
        "    // Frontend should retry ONCE more after a longer delay (10s) to allow\n"
        "    // Render/Supabase to recover. Cap at 2 total auto-retries to prevent loops.\n"
        "    const isTransient = msg.toLowerCase().includes('temporarily unavailable') ||\n"
        "                        msg.toLowerCase().includes('auth_service_unavailable') ||\n"
        "                        msg.toLowerCase().includes('db_timeout')               ||\n"
        "                        msg.toLowerCase().includes('request aborted')          ||\n"
        "                        msg.toLowerCase().includes('try again in');\n"
        "\n"
        "    secureDoLogin._autoRetryCount = (secureDoLogin._autoRetryCount || 0);\n"
        "\n"
        "    if (isTransient && secureDoLogin._autoRetryCount < 2 && !secureDoLogin._retrying) {\n"
        "      secureDoLogin._autoRetryCount += 1;\n"
        "      secureDoLogin._retrying = true;\n"
        "      const retryIn = secureDoLogin._autoRetryCount === 1 ? 8 : 15; // longer on 2nd retry\n"
        "      _showLoginError(errEl,\n"
        "        `⏳ Server warming up (attempt ${secureDoLogin._autoRetryCount}/2)… retrying in ${retryIn}s.`\n"
        "      );\n"
        "      setTimeout(() => {\n"
        "        secureDoLogin._retrying = false;\n"
        "        secureDoLogin();\n"
        "      }, retryIn * 1000);\n"
        "      return;\n"
        "    }",
        "  } catch (err) {\n"
        "    _setBtnLoading(btn, false);\n"
        "\n"
        "    const msg = err.message || 'Login failed';\n"
        "    // v7.4 FIX: Parse retryIn from API response if available\n"
        "    const serverRetryIn = err._retryIn || null;\n"
        "    const display = _mapLoginError(msg);\n"
        "\n"
        "    _showLoginError(errEl, display);\n"
        "    console.warn('[SecureLogin] Authentication failed:', msg);\n"
        "\n"
        "    // ── Auto-retry for 503 AUTH_SERVICE_UNAVAILABLE ────────────────────────\n"
        "    // v7.4: The backend returns retryIn: 5 in the response body.\n"
        "    // Frontend respects that value (clamped: min 5s, max 20s).\n"
        "    // Cap at 2 total auto-retries to prevent infinite loops.\n"
        "    const isTransient = msg.toLowerCase().includes('temporarily unavailable') ||\n"
        "                        msg.toLowerCase().includes('auth_service_unavailable') ||\n"
        "                        msg.toLowerCase().includes('db_timeout')               ||\n"
        "                        msg.toLowerCase().includes('request aborted')          ||\n"
        "                        msg.toLowerCase().includes('service unavailable')      ||\n"
        "                        msg.toLowerCase().includes('try again in');\n"
        "\n"
        "    secureDoLogin._autoRetryCount = (secureDoLogin._autoRetryCount || 0);\n"
        "\n"
        "    if (isTransient && secureDoLogin._autoRetryCount < 2 && !secureDoLogin._retrying) {\n"
        "      secureDoLogin._autoRetryCount += 1;\n"
        "      secureDoLogin._retrying = true;\n"
        "      // v7.4 FIX: Respect server's retryIn guidance (clamped 5–20s)\n"
        "      const defaultDelay = secureDoLogin._autoRetryCount === 1 ? 8 : 15;\n"
        "      const retryIn = serverRetryIn\n"
        "        ? Math.min(Math.max(serverRetryIn, 5), 20)\n"
        "        : defaultDelay;\n"
        "      _showLoginError(errEl,\n"
        "        `⏳ Server warming up (attempt ${secureDoLogin._autoRetryCount}/2)… retrying in ${retryIn}s.`\n"
        "      );\n"
        "      setTimeout(() => {\n"
        "        secureDoLogin._retrying = false;\n"
        "        secureDoLogin();\n"
        "      }, retryIn * 1000);\n"
        "      return;\n"
        "    }",
        'login-secure-patch.js: retryIn from server respected, improved transient detection'
    ),
]

# ═══════════════════════════════════════════════════════════════════
# PATCH 5: js/api-client.js — ensure 503 retryIn is parsed and exposed
# ═══════════════════════════════════════════════════════════════════

# Run patches
files = [
    ('/home/user/webapp/backend/config/supabase.js', supabase_patches),
    ('/home/user/webapp/backend/routes/auth.js', auth_patches),
    ('/home/user/webapp/backend/middleware/auth.js', middleware_patches),
    ('/home/user/webapp/js/login-secure-patch.js', frontend_patches),
]

all_applied = []
all_skipped = []
for filepath, patches in files:
    if os.path.exists(filepath):
        applied, skipped = patch_file(filepath, patches)
        for a in applied:
            print(f'  ✅ {a}')
            all_applied.append(a)
        for s in skipped:
            print(f'  ⚠️  SKIP: {s}')
            all_skipped.append(s)
    else:
        print(f'  ❌ FILE NOT FOUND: {filepath}')

print(f'\nSummary: {len(all_applied)} applied, {len(all_skipped)} skipped')
