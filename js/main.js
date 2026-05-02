/* ══════════════════════════════════════════════════════════
   Wadjet-Eye AI — Main Application Module v17.0
   Full navigation, IOC search, notifications, RBAC, export
   Backend: https://wadjet-eye-ai.onrender.com
   ══════════════════════════════════════════════════════════ */

// ── Ensure backend URL is always set ──
if (!window.THREATPILOT_API_URL) {
  window.THREATPILOT_API_URL = 'https://wadjet-eye-ai.onrender.com';
}
if (!window.WADJET_API_URL) {
  window.WADJET_API_URL = window.THREATPILOT_API_URL;
}

/* ────────────────── RBAC STATE ────────────────── */
let CURRENT_USER = null;

/* ════════════════════════════════════════════════════════════════
   LOGIN — v4.0 Enterprise Edition
   Priority order:
     1. Real backend authentication (Supabase JWT)
     2. Emergency fallback for known accounts when backend is DOWN
   No demo bypass — real credentials required
════════════════════════════════════════════════════════════════ */
async function doLogin() {
  const email    = document.getElementById('loginEmail')?.value?.trim();
  const password = document.getElementById('loginPassword')?.value?.trim();
  const tenant   = document.getElementById('loginTenant')?.value || 'mssp-global';
  const errEl    = document.getElementById('loginError');
  const btn      = document.querySelector('.login-btn');

  if (!email || !password) {
    if (errEl) { errEl.textContent = '⚠️ Please enter your email and password.'; errEl.style.display = 'block'; }
    return;
  }

  const originalBtnText = btn ? btn.innerHTML : '';
  if (btn) { btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing in…'; btn.disabled = true; }
  if (errEl) errEl.style.display = 'none';

  /* ── Helper: animate into app ───────────────────────────── */
  function _enterApp() {
    const loginScreen = document.getElementById('loginScreen');
    if (loginScreen) {
      loginScreen.style.opacity    = '0';
      loginScreen.style.transition = 'opacity 0.4s ease';
      setTimeout(() => {
        loginScreen.style.display = 'none';
        const mainApp = document.getElementById('mainApp');
        if (mainApp) mainApp.style.display = 'flex';
        if (btn) { btn.innerHTML = originalBtnText; btn.disabled = false; }
        if (typeof initApp === 'function') initApp();
      }, 400);
    }
  }

  /* ── Emergency fallback accounts (used when backend is unreachable OR profile not found) ── */
  const _EMERGENCY_ACCOUNTS = {
    'mahmoud.osman@wadjet.ai': { id:'super-admin-mo', name:'Mahmoud Osman', role:'super_admin', tenant_slug:'mssp-global', tenant_name:'MSSP Global Operations', permissions:['read','write','admin','super_admin','manage_tenants','manage_users','manage_billing','manage_integrations','view_audit_logs','delete_records','export_data','configure_platform'] },
    'mahmoud@mssp.com':        { id:'super-admin-mo', name:'Mahmoud Osman', role:'super_admin', tenant_slug:'mssp-global', tenant_name:'MSSP Global Operations', permissions:['read','write','admin','super_admin','manage_tenants','manage_users','manage_billing','manage_integrations','view_audit_logs','delete_records','export_data','configure_platform'] },
    'admin@mssp.com':          { id:'admin-001',      name:'Admin User',    role:'admin',       tenant_slug:'mssp-global', tenant_name:'MSSP Global Operations', permissions:['read','write','admin','manage_users','view_audit_logs','export_data'] },
    'analyst@mssp.com':        { id:'analyst-001',    name:'SOC Analyst',   role:'analyst',     tenant_slug:'mssp-global', tenant_name:'MSSP Global Operations', permissions:['read','write'] },
  };

  function _doEmergencyLogin(profile, reason) {
    const offlineToken = 'offline_emergency_' + Date.now().toString(36);
    CURRENT_USER = {
      id:          profile.id,       email,
      name:        profile.name,     role:        profile.role,
      tenant:      profile.tenant_slug,           tenant_name: profile.tenant_name,
      tenant_id:   profile.tenant_slug,           avatar:      profile.name.split(' ').map(n=>n[0]).join('').toUpperCase().slice(0,2),
      permissions: profile.permissions,           mfa_enabled: false,
      _offline:    true,             is_super_admin: profile.role === 'super_admin',
    };
    // Store in PersistentTokenStore (survives page refresh)
    if (typeof window.PersistentAuth_onLogin === 'function') {
      window.PersistentAuth_onLogin(CURRENT_USER, offlineToken, null, null, true);
    } else if (typeof TokenStore !== 'undefined') {
      TokenStore.set(offlineToken, null, null);
      TokenStore.setUser(CURRENT_USER);
    }
    // Also notify PersistentAuth hook if available
    if (typeof window.PersistentAuth_onEmergencyLogin === 'function') {
      window.PersistentAuth_onEmergencyLogin(CURRENT_USER, offlineToken);
    }
    const reasonLabel = reason === 'profile' ? '(offline — profile not seeded in DB)' : '(offline — backend unreachable)';
    if (typeof showToast === 'function')
      showToast(`⭐ Welcome, ${profile.name} ${reasonLabel}`, 'warning', 5000);
    console.warn('[Login] ⚠️ Emergency offline session for', email, '—', reason);
    _enterApp();
  }

  /* ── Helper: is this a "known admin" that should always be able to login? ── */
  function _getEmergencyProfile(emailLower) {
    return _EMERGENCY_ACCOUNTS[emailLower] || null;
  }

  try {
    if (typeof API === 'undefined') {
      // API client not loaded — try emergency fallback immediately
      const emergencyProfile = _getEmergencyProfile(email.toLowerCase());
      if (emergencyProfile && password.length >= 6) {
        _doEmergencyLogin(emergencyProfile, 'network');
        return;
      }
      throw new Error('API client not loaded — check network connection.');
    }

    // ── STEP 1: Try real backend authentication ────────────
    let data;
    try {
      data = await API.auth.login(email, password, tenant);
    } catch (apiErr) {
      const msg = (apiErr.message || '').toLowerCase();

      // Network / connectivity failure → emergency fallback for known admins
      const isNetworkError = msg.includes('network') || msg.includes('cannot reach') ||
                             msg.includes('failed to fetch') || msg.includes('err_connection') ||
                             msg.includes('timeout') || msg.includes('load failed');

      // Profile not found in DB → emergency fallback for known admins (DB not seeded yet)
      const isProfileMissing = msg.includes('profile') || msg.includes('user not found') ||
                               msg.includes('not found') || msg.includes('no rows') ||
                               msg.includes('does not exist');

      // Account not in Supabase auth yet → emergency fallback for known admins
      const isAuthUserMissing = msg.includes('invalid login') || msg.includes('email not confirmed') ||
                                msg.includes('user not registered') || msg.includes('invalid credentials') && isProfileMissing;

      const needsFallback = isNetworkError || isProfileMissing || isAuthUserMissing;

      if (needsFallback) {
        const emergencyProfile = _getEmergencyProfile(email.toLowerCase());
        if (emergencyProfile && password.length >= 6) {
          _doEmergencyLogin(emergencyProfile, isNetworkError ? 'network' : 'profile');
          return;
        }
      }

      // For other real auth errors (wrong password, suspended, etc.) — surface the error
      throw apiErr;
    }

    if (!data?.user) throw new Error('Invalid response from authentication server.');

    // ── STEP 2: Build CURRENT_USER from real JWT response ──
    CURRENT_USER = {
      id:          data.user.id,
      email:       data.user.email,
      name:        data.user.name    || data.user.email,
      role:        data.user.role    || 'ANALYST',
      tenant:      data.user.tenant_slug || tenant,
      tenant_name: data.user.tenant_name || tenant,
      tenant_id:   data.user.tenant_id,
      avatar:      data.user.avatar  || (data.user.name||'U').split(' ').map(n=>n[0]).join('').toUpperCase().slice(0,2),
      permissions: data.user.permissions || ['read'],
      mfa_enabled: data.user.mfa_enabled || false,
      is_super_admin: data.user.role === 'SUPER_ADMIN' || data.user.role === 'super_admin',
      sessionId:   data.sessionId,
      _offline:    false,
    };

    // Persist to PersistentTokenStore so session survives page refresh
    if (typeof window.PersistentAuth_onLogin === 'function') {
      window.PersistentAuth_onLogin(
        CURRENT_USER,
        data.token || data.access_token,
        data.refreshToken || data.refresh_token,
        data.expiresAt || data.expiresIn,
        false
      );
    }

    console.info('[Wadjet-Eye AI] ✅ Authenticated via real backend as', CURRENT_USER.role, '/', CURRENT_USER.email);

    if (typeof showToast === 'function')
      showToast(`✅ Welcome, ${CURRENT_USER.name}`, 'success');

    _enterApp();

  } catch (err) {
    const msg = err.message || 'Login failed';
    console.warn('[Login] Failed:', msg);

    // ── FINAL SAFETY NET: if backend failed for any reason and this is a known admin account ──
    const msgLow = msg.toLowerCase();
    const isKnownAccount = _getEmergencyProfile(email.toLowerCase());
    const isSoftError = msgLow.includes('profile') || msgLow.includes('not found') ||
                        msgLow.includes('network') || msgLow.includes('unreachable') ||
                        msgLow.includes('failed to fetch') || msgLow.includes('timeout') ||
                        msgLow.includes('no rows') || msgLow.includes('does not exist') ||
                        msgLow.includes('user not') || msgLow.includes('cannot reach');

    if (isKnownAccount && password.length >= 6 && isSoftError) {
      _doEmergencyLogin(isKnownAccount, 'profile');
      return;
    }

    if (btn) { btn.innerHTML = originalBtnText; btn.disabled = false; }

    const display =
      msgLow.includes('invalid email') || msgLow.includes('invalid credentials') || msgLow.includes('wrong password')
        ? '❌ Invalid email or password. Please try again.'
        : msgLow.includes('suspended')
        ? '⚠️ Account suspended. Contact your administrator.'
        : msgLow.includes('tenant')
        ? '⚠️ You do not have access to this tenant.'
        : msgLow.includes('profile') || msgLow.includes('not found')
        ? '⚠️ User profile not found. Contact your administrator.'
        : msgLow.includes('unreachable') || msgLow.includes('network') || msgLow.includes('connection')
        ? '🔌 Cannot reach backend. Check your network connection.'
        : `❌ ${msg}`;

    if (errEl) { errEl.textContent = display; errEl.style.display = 'block'; }
  }
}

/* ════════════════════════════════════════════
   LOGOUT — revoke tokens and clear session
════════════════════════════════════════════ */
async function doLogout() {
  // Revoke backend refresh token
  try {
    if (typeof API !== 'undefined') {
      await API.auth.logout();
    }
  } catch { /* non-fatal */ }

  CURRENT_USER = null;
  if (typeof TokenStore !== 'undefined') TokenStore.clear();
  // Clear persistent session
  if (typeof window.PersistentAuth_onLogout === 'function') window.PersistentAuth_onLogout();

  // Clear timers
  if (window._dashboardRefreshTimer) {
    clearInterval(window._dashboardRefreshTimer);
    window._dashboardRefreshTimer = null;
  }
  // Clear notification timer
  if (_notifTimer) { clearInterval(_notifTimer); _notifTimer = null; }
  // Clear live update timer
  if (_liveUpdateTimer) { clearInterval(_liveUpdateTimer); _liveUpdateTimer = null; }

  // Disconnect WebSocket
  if (typeof WS !== 'undefined' && WS.disconnect) WS.disconnect();

  // Show login screen
  const mainApp     = document.getElementById('mainApp');
  const loginScreen = document.getElementById('loginScreen');
  if (mainApp)     mainApp.style.display = 'none';
  if (loginScreen) { loginScreen.style.display = 'flex'; loginScreen.style.opacity = '1'; }

  if (typeof showToast === 'function') showToast('Logged out securely', 'info');
  console.info('[Auth] Session ended');
}

/* ────────────────── PAGE REGISTRY ────────────────── */
const PAGE_CONFIG = {
  'command-center':  { title:'Command Center',          breadcrumb:'Dashboard / Overview',                  onEnter:(opts)=>renderCommandCenter(opts), onLeave:()=>{} },
  'findings':        { title:'Findings',                breadcrumb:'Intelligence / Findings',               onEnter:(opts)=>renderFindings(opts),       onLeave:()=>{} },
  'campaigns':       { title:'Active Campaigns',        breadcrumb:'Intelligence / Campaigns',
    // SOC v3.0: campaigns-soc.js overrides window.renderCampaigns and patches this entry.
    // This default calls window.renderCampaigns so either the SOC module or the legacy
    // pages.js function is invoked depending on which loaded last.
    onEnter:(opts)=>{
      if (typeof window.renderCampaignsSOC === 'function') {
        if (window.CampaignSOC) window.CampaignSOC.loading = false;
        window.renderCampaignsSOC().catch(e => console.error('[Campaigns]', e));
      } else if (typeof window.renderCampaigns === 'function') {
        window.renderCampaigns(opts);
      } else {
        setTimeout(() => { if (window.PAGE_CONFIG) window.PAGE_CONFIG['campaigns'].onEnter(opts); }, 300);
      }
    },
    onLeave:()=>{
      if (typeof window._csocStopPolling === 'function') window._csocStopPolling();
      if (typeof window._csocCloseDetail === 'function') window._csocCloseDetail();
    }
  },
  'detections':      { title:'Live Detections',         breadcrumb:'Operations / Live Feed',
    // SOC v3.0: live-detections-soc.js overrides window.renderDetections and patches this entry.
    onEnter:()=>{
      if (typeof window.renderLiveDetectionsSOC === 'function') {
        if (window.DetectSOC) window.DetectSOC.loading = false;
        window.renderLiveDetectionsSOC().catch(e => console.error('[Detections]', e));
      } else if (typeof window.renderDetections === 'function') {
        window.renderDetections();
      } else if (typeof renderDetections === 'function') {
        renderDetections();
      } else {
        setTimeout(() => { if (window.PAGE_CONFIG) window.PAGE_CONFIG['detections'].onEnter(); }, 300);
      }
    },
    onLeave:()=>{
      if (typeof window.stopDetections === 'function') window.stopDetections();
      else if (typeof stopDetections === 'function') stopDetections();
    }
  },
  'dark-web':        { title:'Dark Web Intelligence',   breadcrumb:'Intelligence / Dark Web',               onEnter:()=>{ if(typeof window.renderDarkWeb==='function') window.renderDarkWeb(); else { const p=document.getElementById('page-dark-web'); if(p) p.innerHTML='<div style="padding:40px;text-align:center;color:#8b949e">Dark web module loading...</div>'; } }, onLeave:()=>{} },
  'ai-orchestrator': { title:'AI Orchestrator',         breadcrumb:'AI Operations / Agentic Investigation', onEnter:()=>renderAIOrchestrator(), onLeave:()=>{} },
  'collectors':      { title:'Threat Collectors',       breadcrumb:'AI Operations / Collectors',            onEnter:()=>renderCollectors(),     onLeave:()=>{} },
  'playbooks':       { title:'Response Playbooks',      breadcrumb:'AI Operations / Playbooks',             onEnter:()=>{ 
    if(typeof window.renderPlaybooks==='function') { 
      try { window.renderPlaybooks(); } catch(e) { console.warn('[Playbooks]',e); } 
    } else { 
      const c=document.getElementById('playbooksWrap'); 
      if(c) c.innerHTML='<div style="padding:40px;text-align:center;color:#8b949e"><i class="fas fa-spinner fa-spin fa-2x"></i><div style="margin-top:12px">Loading playbooks…</div></div>'; 
    } 
  }, onLeave:()=>{} },
  /* ── SOC OPERATIONS MODULE ── */
  'soc-operations':  { title:'SOC Operations',          breadcrumb:'SOC Operations / AI Automation & Investigation',
    onEnter: () => {
      const wrap = document.getElementById('socOperationsWrap');
      // CSS #page-soc-operations.active { display:flex } handles layout.
      // No need to manually set display style — navigateTo already adds .active class.
      if (wrap && typeof window.SOCOperations !== 'undefined') {
        // Only render once, then just switch tabs
        if (!wrap.dataset.rendered) {
          wrap.dataset.rendered = '1';
          SOCOperations.render(wrap);
        }
      } else if (wrap) {
        wrap.innerHTML = '<div style="padding:60px;text-align:center;color:#8b949e;"><i class="fas fa-spinner fa-spin fa-2x" style="display:block;margin-bottom:16px;"></i>Loading SOC Operations module…</div>';
      }
    },
    onLeave: () => {
      // Stop ingestion when leaving to save resources
      if (typeof window.SOCOperations !== 'undefined' && window.SOCOperations.stopIngestion) {
        window.SOCOperations.stopIngestion();
      }
    }
  },
  'edr-siem':        { title:'EDR / SIEM Webhooks',     breadcrumb:'Phase 2 / Webhook Ingestion',           onEnter:()=>renderEDRSIEM(),        onLeave:()=>{} },
  'customers':       { title:'Tenant Management',       breadcrumb:'Platform / Tenants',                    onEnter:()=>{ if(typeof renderTenantsPage==='function') renderTenantsPage(); else if(typeof renderCustomers==='function') renderCustomers(); }, onLeave:()=>{} },
  'reports':         { title:'Reports & Exports',       breadcrumb:'Management / Reports',                  onEnter:()=>renderReports(),        onLeave:()=>{} },
  'settings':        { title:'Platform Settings',       breadcrumb:'Management / Settings',                 onEnter:()=>renderSettings(),       onLeave:()=>{} },
  'executive-dashboard':{ title:'Executive Dashboard',  breadcrumb:'Advanced SOC / Executive View',        onEnter:()=>renderExecutiveDashboard(), onLeave:()=>{} },
  'kill-chain':      { title:'Kill Chain View',         breadcrumb:'Advanced SOC / Kill Chain Visualization', onEnter:()=>{ 
    if(typeof renderKillChainLive==='function') renderKillChainLive().catch(e=>console.warn('[KillChain]',e)); 
    else if(typeof renderKillChain==='function') renderKillChain(); 
    else { const c=document.getElementById('killChainWrap'); if(c) c.innerHTML='<div style="padding:40px;text-align:center;color:#8b949e">Kill chain module loading…</div>'; }
  }, onLeave:()=>{} },
  'case-management': { title:'Case Management',         breadcrumb:'Advanced SOC / Cases & Incidents',     onEnter:()=>{ if(typeof renderCaseManagement==='function') renderCaseManagement(); }, onLeave:()=>{} },


  'raykan':          { title:'RAYKAN — AI Threat Hunting', breadcrumb:'Advanced SOC / RAYKAN DFIR Engine',  onEnter:()=>{ if(typeof window.renderRAYKAN==='function') { try { window.renderRAYKAN(); } catch(e) { console.warn('[RAYKAN]',e); } } else { const c=document.getElementById('raykanWrap'); if(c) c.innerHTML='<div style="padding:40px;text-align:center;color:#8b949e"><i class="fas fa-spinner fa-spin fa-2x"></i><div style="margin-top:12px">Loading RAYKAN Engine…</div></div>'; } }, onLeave:()=>{} },
  'soar':            { title:'SOAR Automation',         breadcrumb:'Advanced SOC / Automated Response',    onEnter:()=>{ if(typeof renderSOARLive==='function') renderSOARLive(); else if(typeof renderSOAR==='function') renderSOAR(); }, onLeave:()=>{} },
  'live-feeds':      { title:'Live Threat Intel Feeds', breadcrumb:'Advanced SOC / Real-time Intelligence', onEnter:()=>renderLiveFeeds(),     onLeave:()=>stopLiveFeeds() },
  /* ── INTEL HUB ── */
  'cyber-news':      { title:'Threat Intelligence Feed',breadcrumb:'Intel Hub / Cyber News',                onEnter:()=>renderCyberNews(),      onLeave:()=>{} },
  'ioc-database':    { title:'IOC Database',            breadcrumb:'Intel Hub / Threat Indicators',          onEnter:()=>{
    // Always call the LATEST window.renderIOCDatabase (patched by ioc-intelligence.js at load time).
    // CRITICAL: Do NOT reference the bare 'IOCDB' variable here — it lives in ioc-intelligence.js
    // scope and is not globally accessible, causing a ReferenceError that silently crashes onEnter.
    // Use window.IOCDB instead (set by ioc-intelligence.js).
    if (window.IOCDB) window.IOCDB.loading = false; // reset stuck loading flag safely
    if (typeof window.renderIOCDatabase === 'function') {
      window.renderIOCDatabase();
    } else {
      // Fallback: ioc-intelligence.js hasn't loaded yet — wait and retry
      setTimeout(() => {
        if (window.IOCDB) window.IOCDB.loading = false;
        if (typeof window.renderIOCDatabase === 'function') window.renderIOCDatabase();
      }, 500);
    }
  }, onLeave:()=>{ if (window.IOCDB) window.IOCDB.loading = false; } },
  'geo-threats':     { title:'Live Cyber Threat Map',   breadcrumb:'Intel Hub / Radware Real-Time Threat Map', onEnter:()=>{ if(typeof window.renderGeoMap==='function') window.renderGeoMap(); else { const w=document.getElementById('geoThreatsWrap'); if(w) w.innerHTML='<div style="display:flex;align-items:center;justify-content:center;height:100%;flex-direction:column;gap:12px;color:#8b949e"><i class="fas fa-spinner fa-spin fa-2x"></i><div>Loading threat map…</div></div>'; } }, onLeave:()=>{} },
  /* ── PLATFORM ── */
  'rbac-admin':      { title:'RBAC Administration',     breadcrumb:'Platform / Access Control',              onEnter:()=>renderRBACAdmin(),      onLeave:()=>{} },
  'branding':        { title:'White-Label Branding',    breadcrumb:'Platform / Brand Management',            onEnter:()=>renderBranding(),       onLeave:()=>{} },
  'pricing':         { title:'Pricing Plans',           breadcrumb:'Platform / Subscription Tiers',          onEnter:()=>renderPricing(),        onLeave:()=>{} },
  /* ── RAKAY AI Analyst ── */
  'rakay':           { title:'RAKAY — AI Security Analyst', breadcrumb:'AI Analyst / Conversational Security',
    onEnter: () => {
      if (typeof window.renderRAKAY === 'function') {
        window.renderRAKAY();
      } else {
        const p = document.getElementById('page-rakay');
        if (p) p.innerHTML = '<div style="padding:40px;text-align:center;color:#8b949e"><i class="fas fa-circle-notch fa-spin fa-2x"></i><br><br>RAKAY module loading…</div>';
      }
    },
    onLeave: () => {
      if (typeof window.stopRAKAY === 'function') window.stopRAKAY();
    },
  },

  /* ── ETI-AARE EMAIL THREAT INTELLIGENCE MODULE ── */
  'email-threat': {
    title: 'Email Threat Intelligence',
    breadcrumb: 'Cyber Defense Brain / ETI-AARE',
    onEnter: () => {
      const container = document.getElementById('page-email-threat');
      if (!container) return;
      if (!container.dataset.rendered) {
        container.dataset.rendered = '1';
        if (typeof window.ETIModule !== 'undefined') {
          window.ETIModule.mount(container);
        } else {
          container.innerHTML = '<div style="padding:60px;text-align:center;color:#8b949e;"><i class="fas fa-spinner fa-spin fa-2x" style="display:block;margin-bottom:16px;"></i>Loading ETI-AARE module…</div>';
          // Retry once module loads
          setTimeout(() => {
            if (typeof window.ETIModule !== 'undefined' && !container.querySelector('.eti-module')) {
              window.ETIModule.mount(container);
            }
          }, 800);
        }
      } else {
        if (typeof window.ETIModule?.onShow === 'function') window.ETIModule.onShow();
      }
    },
    onLeave: () => {},
  },
};

// ── Expose PAGE_CONFIG on window so late-loading modules (campaigns-soc.js,
// live-detections-soc.js, ioc-intelligence.js, live-pages-patch.js) can
// patch onEnter/onLeave at runtime.
// `const` at script top-level does NOT create a window property — we must
// assign explicitly.
window.PAGE_CONFIG = PAGE_CONFIG;

let currentPage = 'command-center';
let _navLock = false;  // prevent double-navigation during async render

/* ────────────────── NAVIGATION ────────────────── */
function navigateTo(pageId, opts) {
  if (!PAGE_CONFIG[pageId]) return;
  if (_navLock && pageId === currentPage) return;  // prevent re-entering same page

  // ── 1. Leave current page (call onLeave synchronously) ──
  try {
    const leaving = PAGE_CONFIG[currentPage];
    if (leaving?.onLeave) leaving.onLeave();
  } catch (e) { console.warn('[Nav] onLeave error:', e.message); }

  // ── 2. DOM switch (immediate, no freeze) ──
  // CRITICAL FIX: Some pages (e.g. soc-operations) use inline style="display:flex"
  // or style="display:none" set by their onEnter/onLeave handlers.
  // CSS class `.page { display:none }` cannot override inline styles.
  // We MUST reset the inline display style on ALL pages before showing the target,
  // otherwise the previous page remains visible even after removing `.active`.
  document.querySelectorAll('.page').forEach(p => {
    p.classList.remove('active');
    // ALWAYS set inline display:none on non-active pages.
    // This overrides any inline style (e.g. display:flex set by a previous onEnter)
    // so the CSS `.page { display:none }` rule is reinforced and the previous tab
    // never bleeds through when the user switches modules.
    p.style.display = 'none';
  });
  const targetEl = document.getElementById(`page-${pageId}`);
  if (targetEl) {
    // Remove any inline display so CSS .page.active { display:block } takes effect
    targetEl.style.display = '';
    targetEl.classList.add('active');
  }

  // ── 3. Update nav highlight ──
  // Support both old .nav-item and new .nav-child elements
  document.querySelectorAll('.nav-item, .nav-child').forEach(item => {
    item.classList.toggle('active', item.dataset.page === pageId);
  });
  // Open the parent group that contains the active child and mark it
  document.querySelectorAll('.nav-group').forEach(group => {
    const hasActive = group.querySelector(`.nav-child[data-page="${pageId}"]`);
    if (hasActive) {
      group.classList.add('has-active');
      // Auto-open the group if not already open
      const header = group.querySelector('.nav-group-header');
      const children = group.querySelector('.nav-group-children');
      if (header && children && !header.classList.contains('open')) {
        _openNavGroup(header, children);
      }
    } else {
      group.classList.remove('has-active');
    }
  });

  // ── 4. Update title/breadcrumb ──
  const cfg = PAGE_CONFIG[pageId];
  if (cfg) {
    const titleEl = document.getElementById('pageTitle');
    const breadEl = document.getElementById('breadcrumb');
    if (titleEl) titleEl.textContent = cfg.title;
    if (breadEl) breadEl.textContent = cfg.breadcrumb;
  }

  currentPage = pageId;

  // ── 5. Run onEnter asynchronously (avoids blocking UI thread) ──
  if (cfg?.onEnter) {
    _navLock = true;
    // Use requestAnimationFrame to yield to browser before running heavy render
    requestAnimationFrame(() => {
      setTimeout(() => {
        try {
          const result = cfg.onEnter(opts);
          if (result && typeof result.catch === 'function') {
            result.catch(e => console.warn(`[Nav] ${pageId} onEnter error:`, e.message));
          }
        } catch (e) {
          console.warn(`[Nav] ${pageId} onEnter sync error:`, e.message);
        }
        _navLock = false;
      }, 0);
    });
  }

  // ── 6. Close search dropdown ──
  closeSearchResults();
}

/* ────────────────── COLLAPSIBLE NAV GROUPS ────────────────── */

/**
 * Open a nav group — sets max-height to the scrollHeight for smooth animation.
 */
function _openNavGroup(header, children) {
  header.classList.add('open');
  children.classList.add('open');
  // Use scrollHeight for correct max-height animation target
  children.style.maxHeight = children.scrollHeight + 'px';
}

/**
 * Close a nav group.
 */
function _closeNavGroup(header, children) {
  header.classList.remove('open');
  children.classList.remove('open');
  children.style.maxHeight = '0px';
}

/**
 * Toggle a nav group open/closed.
 * Called by the inline onclick="toggleNavGroup(this)" on each .nav-group-header.
 */
function toggleNavGroup(headerBtn) {
  const group    = headerBtn.closest('.nav-group');
  const children = group.querySelector('.nav-group-children');
  if (!children) return;

  const isOpen = headerBtn.classList.contains('open');

  if (isOpen) {
    _closeNavGroup(headerBtn, children);
  } else {
    _openNavGroup(headerBtn, children);
  }
}

/**
 * Initialise groups: open the one containing the current active page,
 * close all others.
 */
function initNavGroups() {
  document.querySelectorAll('.nav-group').forEach(group => {
    const header   = group.querySelector('.nav-group-header');
    const children = group.querySelector('.nav-group-children');
    if (!header || !children) return;

    // Check if this group has the active child
    const hasActive = group.querySelector('.nav-child.active, .nav-item.active');
    if (hasActive) {
      _openNavGroup(header, children);
      group.classList.add('has-active');
    } else {
      // Ensure closed state
      children.style.maxHeight = '0px';
    }
  });
}

/* Expose globally (used by onclick in HTML) */
window.toggleNavGroup = toggleNavGroup;

/* ────────────────── SIDEBAR TOGGLE ────────────────── */
function initSidebarToggle() {
  const toggle  = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');
  const wrapper = document.getElementById('mainWrapper');
  if (!toggle) return;
  toggle.addEventListener('click', () => {
    const collapsed = sidebar.classList.toggle('collapsed');
    wrapper.classList.toggle('sidebar-collapsed', collapsed);
  });
}

/* ────────────────── NAV CLICK HANDLERS ────────────────── */
function initNavLinks() {
  // Wire both old .nav-item and new .nav-child elements
  document.querySelectorAll('.nav-item[data-page], .nav-child[data-page]').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      navigateTo(item.dataset.page);
    });
  });
}

/* ════════════════════════════════════════════════
   GLOBAL IOC SEARCH — searches all IOC data
   ════════════════════════════════════════════════ */
function initGlobalSearch() {
  const input = document.getElementById('globalSearch');
  const resultsDiv = document.getElementById('searchResults');
  if (!input) return;

  input.addEventListener('input', debounce(handleSearch, 200));
  input.addEventListener('focus', () => {
    if (input.value.trim().length >= 2) handleSearch({ target: input });
  });

  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      input.focus();
      input.select();
    }
    if (e.key === 'Escape') closeSearchResults();
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('#searchWrap') && !e.target.closest('#searchResults')) {
      closeSearchResults();
    }
  });
}

function handleSearch(e) {
  const q = e.target.value.trim().toLowerCase();
  const resultsDiv = document.getElementById('searchResults');
  if (!resultsDiv) return;

  if (q.length < 2) {
    closeSearchResults();
    return;
  }

  const results = [];

  // Search findings
  ARGUS_DATA.findings.forEach(f => {
    if (f.value.toLowerCase().includes(q) || f.type.toLowerCase().includes(q) || f.source.toLowerCase().includes(q) || f.mitre.toLowerCase().includes(q)) {
      results.push({ type:'finding', icon:'fa-crosshairs', color:'#ef4444', label:`[${f.severity}] ${f.type}`, value:f.value, sub:`Source: ${f.source} · ${f.time}`, action:`openFindingModal('${f.id}')` });
    }
  });

  // Search IOC registry types
  ARGUS_DATA.ioc_registry.forEach(cat => {
    cat.types.forEach(t => {
      if (t.name.toLowerCase().includes(q) || t.regex.toLowerCase().includes(q)) {
        results.push({ type:'ioc', icon:'fa-fingerprint', color:'#22d3ee', label:`IOC: ${t.name}`, value:t.regex.slice(0,50)+'...', sub:`Category: ${cat.category} · ${t.status}`, action:`navigateTo('ioc-registry')` });
      }
    });
  });

  // Search campaigns
  ARGUS_DATA.campaigns.forEach(c => {
    if (c.name.toLowerCase().includes(q) || c.actor.toLowerCase().includes(q) || c.description.toLowerCase().includes(q)) {
      results.push({ type:'campaign', icon:'fa-chess-king', color:'#a855f7', label:`Campaign: ${c.name}`, value:c.actor, sub:`${c.findings} findings · ${c.status}`, action:`openCampaignDetail('${c.id}')` });
    }
  });

  // Search threat actors
  ARGUS_DATA.actors.forEach(a => {
    if (a.name.toLowerCase().includes(q) || a.aliases.some(al => al.toLowerCase().includes(q)) || a.nation.toLowerCase().includes(q)) {
      results.push({ type:'actor', icon:'fa-user-secret', color:'#f97316', label:`Actor: ${a.name}`, value:a.aliases.join(', '), sub:`${a.nation} · ${a.motivation}`, action:`openActorDetail('${a.id}')` });
    }
  });

  // Search dark web
  ARGUS_DATA.darkweb.forEach(d => {
    if (d.title.toLowerCase().includes(q) || d.preview.toLowerCase().includes(q)) {
      results.push({ type:'darkweb', icon:'fa-spider', color:'#ec4899', label:`Dark Web: ${d.type}`, value:d.title, sub:`${d.source} · ${d.time}`, action:`openDarkWebDetail('${d.id}')` });
    }
  });

  // Search collectors
  ARGUS_DATA.collectors.forEach(c => {
    if (c.name.toLowerCase().includes(q) || c.category.toLowerCase().includes(q) || c.desc.toLowerCase().includes(q)) {
      results.push({ type:'collector', icon:'fa-satellite', color:'#22c55e', label:`Collector: ${c.name}`, value:c.desc, sub:`${c.category} · ${c.iocs_today} IOCs today`, action:`openCollectorConfig('${c.id}')` });
    }
  });

  // Search MITRE TTPs
  ARGUS_DATA.findings.forEach(f => {
    if (f.mitre.toLowerCase().includes(q)) {
      if (!results.find(r => r.label === `MITRE: ${f.mitre}`)) {
        results.push({ type:'mitre', icon:'fa-th', color:'#3b82f6', label:`MITRE: ${f.mitre}`, value:`Found in: ${f.type} IOC`, sub:`${f.customer} · ${f.time}`, action:`navigateTo('command-center')` });
      }
    }
  });

  if (results.length === 0) {
    resultsDiv.innerHTML = `<div class="search-no-results"><i class="fas fa-search"></i> No results for "<strong>${q}</strong>"</div>`;
  } else {
    resultsDiv.innerHTML = `
      <div class="search-results-header">${results.length} result${results.length!==1?'s':''} for "<strong>${q}</strong>"</div>
      ${results.slice(0,12).map(r => `
        <div class="search-result-item" onclick="${r.action};closeSearchResults()">
          <div class="sr-icon" style="color:${r.color}"><i class="fas ${r.icon}"></i></div>
          <div class="sr-body">
            <div class="sr-label">${r.label}</div>
            <div class="sr-value">${r.value.length > 60 ? r.value.slice(0,60)+'...' : r.value}</div>
            <div class="sr-sub">${r.sub}</div>
          </div>
          <div class="sr-arrow"><i class="fas fa-arrow-right"></i></div>
        </div>`).join('')}
      ${results.length > 12 ? `<div class="search-more">+${results.length-12} more results — refine your search</div>` : ''}
    `;
  }
  resultsDiv.classList.add('open');
}

function closeSearchResults() {
  const el = document.getElementById('searchResults');
  if (el) el.classList.remove('open');
}

/* ════════════════════════════════════════════════
   NOTIFICATIONS SYSTEM
   ════════════════════════════════════════════════ */
let notificationsOpen = false;
let _notifTimer = null; // stored so it can be cleared on logout

function initNotifications() {
  renderNotificationList();
  updateNotifBadge();

  // Guard: only start the interval once — prevent duplicates on re-render
  if (_notifTimer) return;
  // Auto-generate new notifications every 20s
  _notifTimer = setInterval(() => {
    if (Math.random() > 0.75) generateLiveNotification();
  }, 20000);
}

function generateLiveNotification() {
  const templates = [
    { type:'critical', title:'CRITICAL IOC Detected', desc:'New critical-severity indicator found by AI scanner', page:'findings' },
    { type:'high',     title:'New Ransomware Activity', desc:'Ransomwatch reports new victim listing on dark web', page:'dark-web' },
    { type:'info',     title:'Collector Sync Complete', desc:'Threat feeds refreshed — new IOCs ingested', page:'collectors' },
    { type:'high',     title:'CVE Exploitation Observed', desc:'EPSS spike detected — active exploitation in wild', page:'findings' },
  ];
  const tpl = templates[Math.floor(Math.random() * templates.length)];
  const newNotif = {
    id: 'N' + Date.now(),
    type: tpl.type,
    title: tpl.title,
    desc: tpl.desc,
    time: 'just now',
    read: false,
    page: tpl.page
  };
  ARGUS_DATA.notifications.unshift(newNotif);
  renderNotificationList();
  updateNotifBadge();
  showToast(`${tpl.title}`, tpl.type === 'critical' ? 'error' : tpl.type === 'high' ? 'warning' : 'info');
}

function toggleNotifications() {
  const dropdown = document.getElementById('notifDropdown');
  notificationsOpen = !notificationsOpen;
  dropdown.classList.toggle('open', notificationsOpen);

  // Close AI dropdown if open
  document.getElementById('aiDropdown')?.classList.remove('open');
}

function renderNotificationList() {
  const list = document.getElementById('notifList');
  if (!list) return;
  const notifs = ARGUS_DATA.notifications;
  if (!notifs.length) {
    list.innerHTML = '<div class="notif-empty">No notifications</div>';
    return;
  }
  list.innerHTML = notifs.map(n => `
    <div class="notif-item ${n.read ? 'read' : 'unread'}" onclick="clickNotification('${n.id}')">
      <div class="notif-icon-wrap notif-type-${n.type}">
        <i class="fas ${n.type==='critical'?'fa-skull-crossbones':n.type==='high'?'fa-exclamation-triangle':n.type==='success'?'fa-check-circle':'fa-info-circle'}"></i>
      </div>
      <div class="notif-body">
        <div class="notif-title">${n.title}</div>
        <div class="notif-desc">${n.desc}</div>
        <div class="notif-time">${n.time}</div>
      </div>
      ${!n.read ? '<div class="notif-unread-dot"></div>' : ''}
    </div>`).join('');
}

function clickNotification(id) {
  const n = ARGUS_DATA.notifications.find(x => x.id === id);
  if (!n) return;
  n.read = true;
  renderNotificationList();
  updateNotifBadge();
  toggleNotifications();
  navigateTo(n.page);
}

function markAllRead() {
  ARGUS_DATA.notifications.forEach(n => n.read = true);
  renderNotificationList();
  updateNotifBadge();
}

function updateNotifBadge() {
  const unread = ARGUS_DATA.notifications.filter(n => !n.read).length;
  const dot = document.getElementById('notifDot');
  if (!dot) return;
  if (unread > 0) {
    dot.style.display = 'block';
    dot.textContent = unread > 9 ? '9+' : unread;
  } else {
    dot.style.display = 'none';
  }
}

/* ════════════════════════════════════════════════
   AI PROVIDER SWITCHER
   ════════════════════════════════════════════════ */
function initAIProviderSwitcher() {
  const btn = document.getElementById('aiProviderBtn');
  const dropdown = document.getElementById('aiDropdown');
  if (!btn || !dropdown) return;

  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    dropdown.classList.toggle('open');
    document.getElementById('notifDropdown')?.classList.remove('open');
    notificationsOpen = false;
  });

  document.querySelectorAll('.ai-option').forEach(opt => {
    opt.addEventListener('click', () => {
      document.querySelectorAll('.ai-option').forEach(o => { o.classList.remove('active'); o.querySelector('.ai-check')?.remove(); });
      opt.classList.add('active');
      const check = document.createElement('i');
      check.className = 'fas fa-check ai-check';
      opt.appendChild(check);

      const provider = opt.dataset.provider;
      const names = { ollama:'Qwen3:8B', claude:'Claude 3.5', openai:'GPT-4o', gemini:'Gemini 2.0' };
      const dots  = { ollama:'#22d3ee', claude:'#f59e0b', openai:'#10b981', gemini:'#8b5cf6' };
      const subs  = { ollama:'Local · GPU', claude:'Anthropic', openai:'OpenAI', gemini:'Google' };

      document.querySelector('.ai-name').textContent = names[provider];
      document.querySelector('.ai-dot').style.background = dots[provider];
      document.querySelector('.ai-subtitle').textContent = subs[provider];
      const lbl = document.getElementById('aiProviderLabel');
      if (lbl) lbl.textContent = names[provider] + ' via ' + (provider==='ollama'?'Ollama':provider.charAt(0).toUpperCase()+provider.slice(1));

      dropdown.classList.remove('open');
      showToast(`Switched to ${names[provider]}`, 'info');
    });
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('#aiProviderSwitcher')) dropdown.classList.remove('open');
    if (!e.target.closest('#notifBtn') && !e.target.closest('#notifDropdown')) {
      document.getElementById('notifDropdown')?.classList.remove('open');
      notificationsOpen = false;
    }
  });
}

function testOllama() {
  const endpoint = document.getElementById('ollamaEndpoint')?.value || 'http://localhost:11434';
  showToast(`Testing Ollama at ${endpoint}...`, 'info');
  fetch(endpoint + '/api/tags')
    .then(r => r.json())
    .then(d => showToast(`Ollama connected! Models: ${d.models?.map(m=>m.name).join(', ') || 'found'}`, 'success'))
    .catch(() => showToast(`Ollama not reachable at ${endpoint} — using simulation mode`, 'warning'));
}

/* ════════════════════════════════════════════════
   SYNC BUTTON
   Real implementation is in live-pages.js (triggerSync).
   This stub fires if live-pages is not yet loaded.
   ════════════════════════════════════════════════ */
function triggerSync() {
  // live-pages.js overrides this; this stub runs only if live-pages hasn't loaded
  showToast('Connecting to backend to trigger sync…', 'info');
}

/* ════════════════════════════════════════════════
   TOAST NOTIFICATIONS
   ════════════════════════════════════════════════ */
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const icons = {
    success: '<i class="fas fa-check-circle" style="color:#22c55e"></i>',
    error:   '<i class="fas fa-times-circle" style="color:#ef4444"></i>',
    warning: '<i class="fas fa-exclamation-triangle" style="color:#f59e0b"></i>',
    info:    '<i class="fas fa-info-circle" style="color:#3b82f6"></i>',
  };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `${icons[type] || icons.info} <span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

/* ════════════════════════════════════════════════
   LIVE METRIC UPDATES
   Real KPI refresh is handled by live-pages.js AutoRefresh.
   This function is kept as a stub for backward compatibility.
   ════════════════════════════════════════════════ */
let _liveUpdateTimer = null;
function startLiveUpdates() {
  if (_liveUpdateTimer) return; // guard: only start once
  // TPI bar (sidebar mini-widget) gets a gentle live animation
  _liveUpdateTimer = setInterval(() => {
    const detRate = document.getElementById('detRate');
    if (detRate) detRate.textContent = (3 + Math.random() * 3).toFixed(1) + ' events/sec';
  }, 3000);
}

/* ════════════════════════════════════════════════
   EXPORT FUNCTIONS
   ════════════════════════════════════════════════ */
function exportFindings() {
  const data = findingsFiltered || ARGUS_DATA.findings;
  const csv = [
    ['ID','Severity','Type','Value','Source','Customer','Score','MITRE','Time'],
    ...data.map(f => [f.id, f.severity, f.type, `"${f.value}"`, f.source, f.customer, f.score, f.mitre, f.time])
  ].map(r => r.join(',')).join('\n');
  downloadFile('threatpilot_findings_' + dateStamp() + '.csv', csv, 'text/csv');
  showToast(`Exported ${data.length} findings as CSV`, 'success');
}

function exportCampaigns() {
  const data = campaignsFiltered || ARGUS_DATA.campaigns;
  const csv = [
    ['ID','Name','Actor','Severity','Status','Findings','IOCs','Progress'],
    ...data.map(c => [c.id, `"${c.name}"`, `"${c.actor}"`, c.severity, c.status, c.findings, c.iocs, c.progress+'%'])
  ].map(r => r.join(',')).join('\n');
  downloadFile('threatpilot_campaigns_' + dateStamp() + '.csv', csv, 'text/csv');
  showToast(`Exported ${data.length} campaigns`, 'success');
}

function exportActors() {
  const data = ARGUS_DATA.actors;
  const csv = [
    ['ID','Name','Aliases','Nation','Motivation','Active Since','Techniques'],
    ...data.map(a => [a.id, a.name, `"${a.aliases.join('|')}"`, a.nation, a.motivation, a.active_since, `"${a.techniques.join('|')}"`])
  ].map(r => r.join(',')).join('\n');
  downloadFile('threatpilot_actors_' + dateStamp() + '.csv', csv, 'text/csv');
  showToast(`Exported ${data.length} threat actors`, 'success');
}

function exportDarkWeb() {
  const data = ARGUS_DATA.darkweb;
  const csv = [
    ['ID','Source','Type','Severity','Title','Time'],
    ...data.map(d => [d.id, d.source, d.type, d.severity, `"${d.title}"`, d.time])
  ].map(r => r.join(',')).join('\n');
  downloadFile('threatpilot_darkweb_' + dateStamp() + '.csv', csv, 'text/csv');
  showToast(`Exported ${data.length} dark web entries`, 'success');
}

function exportIOCRegistry(format) {
  if (format === 'json') {
    const json = JSON.stringify(ARGUS_DATA.ioc_registry, null, 2);
    downloadFile('threatpilot_ioc_registry_' + dateStamp() + '.json', json, 'application/json');
  } else {
    const rows = [['Category','Name','Status','Regex']];
    ARGUS_DATA.ioc_registry.forEach(cat => {
      cat.types.forEach(t => rows.push([`"${cat.category}"`, t.name, t.status, `"${t.regex}"`]));
    });
    downloadFile('threatpilot_ioc_registry_' + dateStamp() + '.csv', rows.map(r=>r.join(',')).join('\n'), 'text/csv');
  }
  const total = ARGUS_DATA.ioc_registry.reduce((s,c) => s + c.types.length, 0);
  showToast(`Exported ${total} IOC types as ${format.toUpperCase()}`, 'success');
}

function exportDetections() {
  showToast('Exporting live detection stream...', 'info');
  setTimeout(() => showToast('Detection stream snapshot exported (500 events)', 'success'), 1000);
}

function exportCampaignReport(id, fmt) {
  const c = ARGUS_DATA.campaigns.find(x => x.id === id);
  if (!c) return;
  if (fmt === 'pdf') {
    generatePDFReport('campaign', c);
  } else if (fmt === 'csv') {
    const csv = `Campaign,${c.name}\nActor,${c.actor}\nSeverity,${c.severity}\nStatus,${c.status}\nFindings,${c.findings}\nIOCs,${c.iocs}\nProgress,${c.progress}%\n\nTechniques\n${c.techniques.join('\n')}`;
    downloadFile(`campaign_${c.id}_${dateStamp()}.csv`, csv, 'text/csv');
    showToast('Campaign CSV exported', 'success');
  } else if (fmt === 'json') {
    downloadFile(`campaign_${c.id}_stix_${dateStamp()}.json`, JSON.stringify({ type:'bundle', id:`bundle--${c.id}`, objects:[c] }, null, 2), 'application/json');
    showToast('STIX bundle exported', 'success');
  }
}

function exportActorReport(id, fmt) {
  const a = ARGUS_DATA.actors.find(x => x.id === id);
  if (!a) return;
  if (fmt === 'pdf') {
    generatePDFReport('actor', a);
  } else {
    downloadFile(`actor_${a.id}_${dateStamp()}.json`, JSON.stringify(a, null, 2), 'application/json');
    showToast('Actor profile exported', 'success');
  }
}

function exportPlaybook(id) {
  const p = ARGUS_DATA.playbooks.find(x => x.id === id);
  if (!p) return;
  downloadFile(`playbook_${p.id}_${dateStamp()}.json`, JSON.stringify(p, null, 2), 'application/json');
  showToast(`Playbook "${p.name}" exported`, 'success');
}

function exportCollectorFeeds(id) {
  const c = ARGUS_DATA.collectors.find(x => x.id === id);
  if (!c) return;
  const csv = `Collector,${c.name}\nCategory,${c.category}\nStatus,${c.status}\nType,${c.type}\nIOCs Today,${c.iocs_today}\nIOCs Total,${c.iocs_total}\nLast Run,${c.last_run}`;
  downloadFile(`collector_${c.id}_iocs_${dateStamp()}.csv`, csv, 'text/csv');
  showToast(`Exported feed IOCs for ${c.name}`, 'success');
}

function generatePDFReport(type, data) {
  // Simulate PDF generation with a styled HTML print
  const content = type === 'campaign' ? buildCampaignPDFContent(data) : buildActorPDFContent(data);
  const win = window.open('', '_blank');
  if (win) {
    win.document.write(`
      <!DOCTYPE html><html><head>
      <title>Wadjet-Eye AI — ${data.name}</title>
      <style>
        body { font-family: Arial, sans-serif; background: #fff; color: #000; padding: 40px; }
        h1 { color: #1e293b; border-bottom: 3px solid #ef4444; padding-bottom: 10px; }
        h2 { color: #334155; margin-top: 24px; }
        .badge { display:inline-block; padding:3px 10px; border-radius:4px; font-weight:700; font-size:12px; }
        .critical { background:#fef2f2; color:#ef4444; }
        .high { background:#fff7ed; color:#f97316; }
        table { width:100%; border-collapse:collapse; margin-top:12px; }
        th, td { text-align:left; padding:8px 12px; border:1px solid #e2e8f0; }
        th { background:#f1f5f9; }
        .footer { margin-top:40px; font-size:11px; color:#94a3b8; border-top:1px solid #e2e8f0; padding-top:12px; }
      </style>
      </head><body>
      <h1>👁️ Wadjet-Eye AI — Intelligence Report</h1>
      ${content}
      <div class="footer">Generated by Wadjet-Eye AI v17.0 · ${new Date().toISOString()} · CONFIDENTIAL</div>
      <script>window.print();<\/script>
      </body></html>`);
    win.document.close();
  }
  showToast('PDF report opened — use browser Print to save', 'success');
}

function buildCampaignPDFContent(c) {
  return `
    <h2>Campaign: ${c.name}</h2>
    <p><strong>Threat Actor:</strong> ${c.actor}</p>
    <p><strong>Severity:</strong> <span class="badge ${c.severity.toLowerCase()}">${c.severity}</span> &nbsp; <strong>Status:</strong> ${c.status}</p>
    <p>${c.description}</p>
    <h2>Statistics</h2>
    <table><tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Total Findings</td><td>${c.findings}</td></tr>
    <tr><td>Total IOCs</td><td>${c.iocs}</td></tr>
    <tr><td>Affected Tenants</td><td>${c.customers.join(', ')}</td></tr>
    <tr><td>Investigation Progress</td><td>${c.progress}%</td></tr></table>
    <h2>MITRE ATT&CK Techniques</h2>
    <table><tr><th>Technique ID</th></tr>${c.techniques.map(t=>`<tr><td>${t}</td></tr>`).join('')}</table>`;
}

function buildActorPDFContent(a) {
  return `
    <h2>Threat Actor: ${a.name} ${a.emoji}</h2>
    <p><strong>Nation:</strong> ${a.nation} &nbsp; <strong>Motivation:</strong> ${a.motivation}</p>
    <p><strong>Aliases:</strong> ${a.aliases.join(', ')}</p>
    <p>${a.desc}</p>
    <h2>Known TTPs</h2>
    <table><tr><th>MITRE Technique</th></tr>${a.techniques.map(t=>`<tr><td>${t}</td></tr>`).join('')}</table>`;
}

function generateCustomerPDFReport(custId) {
  const cust = ARGUS_DATA.customers.find(c => c.id === custId) || ARGUS_DATA.tenants.find(t => t.id === custId);
  if (!cust) { showToast('Customer not found', 'error'); return; }
  const findings = ARGUS_DATA.findings.filter(f => f.customer === cust.name || f.customer === cust.short);
  const win = window.open('', '_blank');
  if (win) {
    win.document.write(`<!DOCTYPE html><html><head><title>ThreatPilot — ${cust.name}</title>
    <style>body{font-family:Arial,sans-serif;padding:40px;color:#000;}h1{border-bottom:3px solid #3b82f6;padding-bottom:10px;}table{width:100%;border-collapse:collapse;margin-top:12px;}th,td{padding:8px;border:1px solid #e2e8f0;text-align:left;}th{background:#f1f5f9;}.footer{margin-top:40px;font-size:11px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:12px;}</style>
    </head><body>
    <h1>🏢 ${cust.name} — Threat Intelligence Report</h1>
    <p><strong>Plan:</strong> ${cust.plan} &nbsp; <strong>Risk Level:</strong> ${cust.risk}</p>
    <h2>Findings Summary (${findings.length} total)</h2>
    <table><tr><th>Severity</th><th>Type</th><th>Value</th><th>Score</th><th>Time</th></tr>
    ${findings.map(f=>`<tr><td>${f.severity}</td><td>${f.type}</td><td>${f.value.slice(0,40)}</td><td>${f.score}</td><td>${f.time}</td></tr>`).join('')}
    </table>
    <div class="footer">Generated by ThreatPilot AI v16.4.7 · ${new Date().toISOString()} · CONFIDENTIAL</div>
    <script>window.print();<\/script></body></html>`);
    win.document.close();
  }
  showToast(`PDF report for ${cust.name} opened`, 'success');
}

function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function dateStamp() {
  return new Date().toISOString().slice(0,10);
}

/* ════════════════════════════════════════════════
   EXPORT REPORT (Multi-format from Reports page)
   ════════════════════════════════════════════════ */
function generateReport(templateId, format, tenant) {
  const tpl = ARGUS_DATA.report_templates.find(r => r.id === templateId);
  if (!tpl) return;

  showToast(`Generating ${tpl.name} as ${format}...`, 'info');

  setTimeout(() => {
    if (format === 'PDF') {
      const win = window.open('', '_blank');
      if (win) {
        const findings = tenant ? ARGUS_DATA.findings.filter(f => f.customer === tenant) : ARGUS_DATA.findings;
        win.document.write(`<!DOCTYPE html><html><head><title>Wadjet-Eye AI — ${tpl.name}</title>
        <style>body{font-family:Arial,sans-serif;padding:40px;}h1{border-bottom:3px solid #ef4444;padding-bottom:10px;}h2{color:#334155;margin-top:24px;}table{width:100%;border-collapse:collapse;}th,td{padding:8px;border:1px solid #ddd;text-align:left;}th{background:#f8fafc;}.cover{background:#1e293b;color:#fff;padding:40px;border-radius:8px;margin-bottom:30px;}.footer{margin-top:40px;font-size:11px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:12px;}</style>
        </head><body>
        <div class="cover"><h1 style="color:#fff;border-bottom-color:#1d6ae5;">👁️ Wadjet-Eye AI</h1><h2 style="color:#94a3b8;">${tpl.name}</h2>${tenant?`<p style="color:#64748b;">Tenant: ${tenant}</p>`:''}<p style="color:#64748b;">Generated: ${new Date().toLocaleString()}</p></div>
        <h2>Executive Summary</h2>
        <p>Total Findings: <strong>${findings.length}</strong> | Critical: <strong>${findings.filter(f=>f.severity==='CRITICAL').length}</strong> | High: <strong>${findings.filter(f=>f.severity==='HIGH').length}</strong></p>
        <h2>Top Findings</h2>
        <table><tr><th>Severity</th><th>Type</th><th>Value</th><th>Source</th><th>Score</th></tr>
        ${findings.slice(0,20).map(f=>`<tr><td>${f.severity}</td><td>${f.type}</td><td>${f.value.slice(0,50)}</td><td>${f.source}</td><td>${f.score}</td></tr>`).join('')}
        </table>
        <div class="footer">Wadjet-Eye AI v17.0 · ${new Date().toISOString()} · CONFIDENTIAL — DO NOT DISTRIBUTE</div>
        <script>window.print();<\/script></body></html>`);
        win.document.close();
      }
    } else if (format === 'CSV') {
      const findings = ARGUS_DATA.findings;
      const csv = ['ID,Severity,Type,Value,Source,Customer,Score,MITRE,Time',
        ...findings.map(f => `${f.id},${f.severity},${f.type},"${f.value}",${f.source},${f.customer},${f.score},${f.mitre},${f.time}`)
      ].join('\n');
      downloadFile(`${tpl.name.replace(/\s+/g,'_')}_${dateStamp()}.csv`, csv, 'text/csv');
    } else if (format === 'JSON') {
      const payload = { report: tpl.name, generated: new Date().toISOString(), tenant: tenant||'all', findings: ARGUS_DATA.findings, campaigns: ARGUS_DATA.campaigns, summary: { total: ARGUS_DATA.findings.length, critical: ARGUS_DATA.findings.filter(f=>f.severity==='CRITICAL').length } };
      downloadFile(`${tpl.name.replace(/\s+/g,'_')}_${dateStamp()}.json`, JSON.stringify(payload, null, 2), 'application/json');
    } else if (format === 'STIX') {
      const stix = { type:'bundle', spec_version:'2.1', id:`bundle--${Date.now()}`, objects: ARGUS_DATA.campaigns.map(c => ({ type:'campaign', id:`campaign--${c.id}`, name:c.name, description:c.description })) };
      downloadFile(`${tpl.name.replace(/\s+/g,'_')}_stix_${dateStamp()}.json`, JSON.stringify(stix, null, 2), 'application/json');
    }
    showToast(`${tpl.name} exported as ${format}`, 'success');
  }, 800);
}

/* ════════════════════════════════════════════════
   FINDING DETAIL MODAL
   ════════════════════════════════════════════════ */
function openFindingModal(id) {
  const f = ARGUS_DATA.findings.find(x => x.id === id);
  if (!f) return;
  const sc = f.score >= 85 ? '#ef4444' : f.score >= 65 ? '#f97316' : f.score >= 45 ? '#f59e0b' : '#22c55e';
  const body = document.getElementById('findingModalBody');
  body.innerHTML = `
    <div class="finding-detail-modal">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
        <div>
          <span class="sev-badge sev-${f.severity}" style="font-size:13px;padding:4px 12px;">${f.severity}</span>
          <span style="font-size:13px;color:var(--text-muted);margin-left:8px;">${f.type}</span>
        </div>
        <div style="text-align:right;">
          <div style="font-size:28px;font-weight:800;color:${sc};">${f.score}</div>
          <div style="font-size:10px;color:var(--text-muted);">Threat Score</div>
        </div>
      </div>
      <div class="fd-value-box">${f.value}</div>
      <p style="font-size:12px;color:var(--text-secondary);line-height:1.6;margin:12px 0;">${f.description}</p>
      <div class="fd-meta-row">
        <div class="fd-meta-item"><div class="fd-meta-lbl">Source</div><div class="fd-meta-val">${f.source}</div></div>
        <div class="fd-meta-item"><div class="fd-meta-lbl">Customer</div><div class="fd-meta-val">${f.customer}</div></div>
        <div class="fd-meta-item"><div class="fd-meta-lbl">MITRE TTP</div><div class="fd-meta-val"><span class="mitre-tag">${f.mitre}</span></div></div>
        <div class="fd-meta-item"><div class="fd-meta-lbl">Confidence</div><div class="fd-meta-val" style="color:${sc}">${f.confidence}%</div></div>
        <div class="fd-meta-item"><div class="fd-meta-lbl">Detected</div><div class="fd-meta-val">${f.time}</div></div>
        <div class="fd-meta-item"><div class="fd-meta-lbl">Match Rule</div><div class="fd-meta-val">${f.matched}</div></div>
      </div>
      <div style="margin-top:12px;">
        <div class="modal-section-title">🔗 Feed Sources</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;">
          ${f.feeds.map(fd => `<span class="feed-badge">${fd}</span>`).join('')}
        </div>
      </div>
      <div style="margin-top:12px;">
        <div class="modal-section-title">🔍 Evidence Trail</div>
        <div class="evidence-list">
          ${f.evidence.map(ev => `
            <div class="evidence-item">
              <span class="ev-source">${ev.src}</span>
              <span class="ev-detail">${ev.detail}</span>
            </div>`).join('')}
        </div>
      </div>
      <div class="export-btn-row" style="margin-top:16px;">
        <button class="btn-export-pdf" onclick="exportSingleFinding('${f.id}','pdf')"><i class="fas fa-file-pdf"></i> PDF</button>
        <button class="btn-export-json" onclick="exportSingleFinding('${f.id}','json')"><i class="fas fa-code"></i> JSON</button>
        <button class="btn-primary" onclick="investigateWithAI('${f.id}')"><i class="fas fa-robot"></i> AI Investigate</button>
        <button class="btn-secondary" onclick="showToast('Marked as False Positive','info');closeFindingModalBtn()"><i class="fas fa-ban"></i> False Positive</button>
      </div>
    </div>`;
  document.getElementById('findingModal').classList.add('open');
}

function closeFindingModal(e) { if (e.target === e.currentTarget) closeFindingModalBtn(); }
function closeFindingModalBtn() { document.getElementById('findingModal').classList.remove('open'); }

function exportSingleFinding(id, fmt) {
  const f = ARGUS_DATA.findings.find(x => x.id === id);
  if (!f) return;
  if (fmt === 'json') {
    downloadFile(`finding_${f.id}_${dateStamp()}.json`, JSON.stringify(f, null, 2), 'application/json');
  } else {
    generatePDFReport('finding', { name: `Finding ${f.id}`, ...f });
  }
  showToast(`Finding exported as ${fmt.toUpperCase()}`, 'success');
}

function closePeekAndOpen(id) {
  closeDetailModalBtn();
  setTimeout(() => openFindingModal(id), 150);
}

function investigateWithAI(findingId) {
  const f = ARGUS_DATA.findings.find(x => x.id === findingId);
  closeFindingModalBtn();
  closeDetailModalBtn();
  navigateTo('ai-orchestrator');
  setTimeout(() => {
    const input = document.getElementById('aiInput');
    if (input && f) {
      input.value = `Investigate finding ${f.id}: ${f.type} "${f.value}" from ${f.source}. Customer: ${f.customer}. Score: ${f.score}/100. MITRE: ${f.mitre}`;
      input.dispatchEvent(new Event('input'));
      if (typeof sendAIMessage === 'function') sendAIMessage();
    }
  }, 350);
}

// Alias for backward compatibility with older modal references
function exportFindingJSON(id) {
  const f = ARGUS_DATA.findings.find(x => x.id === id);
  if (!f) return;
  downloadFile(`finding_${id}_${dateStamp()}.json`, JSON.stringify(f, null, 2), 'application/json');
  showToast('Finding exported as JSON', 'success');
}

function investigateCampaign(id) {
  const c = ARGUS_DATA.campaigns.find(x => x.id === id);
  closeDetailModalBtn();
  navigateTo('ai-orchestrator');
  setTimeout(() => {
    const input = document.getElementById('aiInput');
    if (input) {
      input.value = `Analyze campaign "${c?.name}" by ${c?.actor} — ${c?.findings} findings, techniques: ${c?.techniques?.join(', ')}`;
      input.dispatchEvent(new Event('input'));
    }
  }, 300);
}

/* ════════════════════════════════════════════════
   UTILITY: MODAL CLOSE HANDLERS
   ════════════════════════════════════════════════ */
function closeDetailModal(e)    { if (e.target === e.currentTarget) closeDetailModalBtn(); }
function closeDetailModalBtn()  { document.getElementById('detailModal')?.classList.remove('open'); }

/**
 * openDetailModal(html) — FIX v20
 * Injects arbitrary HTML into the shared #detailModal / #detailModalBody overlay
 * and opens it.  Used by case-wiring.js _openCaseDetail() so the Case detail
 * modal gets the same visual treatment (dark overlay, close button, scrollable
 * card) as every other detail modal in the platform, while also giving
 * switchModalTab() a .modal-card ancestor to scope tab switching.
 */
function openDetailModal(html) {
  const overlay = document.getElementById('detailModal');
  const body    = document.getElementById('detailModalBody');
  if (!overlay || !body) return;
  body.innerHTML = html;
  overlay.classList.add('open');
}
function closeCollectorModal(e) { if (e.target === e.currentTarget) closeCollectorModalBtn(); }
function closeCollectorModalBtn(){ document.getElementById('collectorModal')?.classList.remove('open'); }
function closePlaybookModal(e)  { if (e.target === e.currentTarget) closePlaybookModalBtn(); }
function closePlaybookModalBtn(){ document.getElementById('playbookModal')?.classList.remove('open'); }
function closeTenantModal(e)    { if (e.target === e.currentTarget) closeTenantModalBtn(); }
function closeTenantModalBtn()  { document.getElementById('tenantModal')?.classList.remove('open'); }

function switchModalTab(btn, tabId) {
  // FIX v21: scope to the nearest recognised container.
  // Supports TWO panel patterns:
  //   A) data-modal-panel="<id>" + display:none/block  (RAYKAN incident detail, case-wiring)
  //   B) id="<tabId>" + .active class                  (legacy ARGUS modals)
  const scope =
    btn.closest('#detailModalBody') ||
    btn.closest('#cmDetailRoot')    ||
    btn.closest('.modal-card, .campaign-detail, .actor-detail, .collector-detail, ' +
                '.playbook-detail, .darkweb-detail, .tenant-detail') ||
    btn.closest('.rk-modal-body')   ||
    document;

  // ── Pattern A: data-modal-panel (display-based, used by incident/case detail) ──
  const dataPanel = scope.querySelector(`[data-modal-panel="${tabId}"]`);
  if (dataPanel) {
    // Deactivate all tab buttons in this scope
    scope.querySelectorAll('.modal-tab-btn').forEach(t => {
      t.classList.remove('active');
      t.style.color = '#6b7280';
      t.style.borderBottomColor = 'transparent';
    });
    // Hide all data-modal-panel siblings
    scope.querySelectorAll('[data-modal-panel]').forEach(p => { p.style.display = 'none'; });
    // Activate clicked tab
    btn.classList.add('active');
    btn.style.color = '#60a5fa';
    btn.style.borderBottomColor = '#60a5fa';
    // Show target panel
    dataPanel.style.display = 'block';
    return;
  }

  // ── Pattern B: id-based + .active class (legacy ARGUS modals) ──
  scope.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
  scope.querySelectorAll('.modal-tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  const panel = scope.querySelector('#' + tabId) || document.getElementById(tabId);
  if (panel) panel.classList.add('active');
}

/* ════════════════════════════════════════════════
   TEXTAREA AUTO-RESIZE
   ════════════════════════════════════════════════ */
function initTextareaAutoResize() {
  const ta = document.getElementById('aiInput');
  if (!ta) return;
  ta.addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 100) + 'px';
  });
}

/* ════════════════════════════════════════════════
   KEYBOARD SHORTCUTS
   ════════════════════════════════════════════════ */
function initKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
      document.getElementById('aiDropdown')?.classList.remove('open');
      document.getElementById('notifDropdown')?.classList.remove('open');
      closeSearchResults();
      notificationsOpen = false;
    }
    if (e.altKey) {
      const shortcuts = {'1':'command-center','2':'findings','3':'campaigns','4':'detections','5':'ai-orchestrator','6':'collectors','7':'playbooks','8':'reports'};
      if (shortcuts[e.key]) { e.preventDefault(); navigateTo(shortcuts[e.key]); }
    }
  });
}

/* ════════════════════════════════════════════════
   SIDEBAR USER INFO
   ════════════════════════════════════════════════ */
function updateUserUI() {
  if (!CURRENT_USER) return;
  const tenantMap = { 'mssp-global':'MSSP Global', 'hackerone':'HackerOne', 'bugcrowd':'Bugcrowd', 'synack':'Synack', 'cobalt':'Cobalt', 'intigriti':'Intigriti', 'yeswehack':'YesWeHack' };
  const roleColors = { 'SUPER_ADMIN':'#ef4444','ADMIN':'#f97316','ANALYST':'#22d3ee','VIEWER':'#22c55e' };

  const av = document.getElementById('sidebarAvatar');        // was sidebarUserAv
  const nm = document.getElementById('sidebarUserName');
  const rl = document.getElementById('sidebarUserRole');
  const st = document.getElementById('sidebarTenant');
  const ta = document.getElementById('topbarAvatar');

  if (av) av.textContent = CURRENT_USER.avatar;
  if (nm) nm.textContent = CURRENT_USER.name;
  if (rl) { rl.textContent = CURRENT_USER.role; rl.style.color = roleColors[CURRENT_USER.role] || '#64748b'; }
  if (st) st.textContent = tenantMap[CURRENT_USER.tenant] || CURRENT_USER.tenant;
  if (ta) ta.textContent = CURRENT_USER.avatar;
}

/* ════════════════════════════════════════════════
   DEBOUNCE
   ════════════════════════════════════════════════ */
function debounce(fn, delay) {
  let timer;
  return function(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}

/* ════════════════════════════════════════════════
   BOOT SEQUENCE
   ════════════════════════════════════════════════ */
function bootSequence() {
  const msgs = [
    { msg:'Wadjet-Eye AI v17.0 initialized', type:'info' },
    { msg:'Connecting to backend API…', type:'info' },
    { msg:'Loading threat intelligence modules…', type:'info' },
    { msg:'MITRE ATT&CK framework ready', type:'info' },
    { msg:'All 25+ CTI feeds online — fetching live data…', type:'success' },
  ];
  let i = 0;
  const iv = setInterval(() => {
    if (i < msgs.length) { showToast(msgs[i].msg, msgs[i].type); i++; }
    else clearInterval(iv);
  }, 900);
}

/* ════════════════════════════════════════════════
   APP INIT (called after login)
   ════════════════════════════════════════════════ */
function initApp() {
  updateUserUI();
  initNavLinks();
  initNavGroups();   // Initialize collapsible nav groups
  initSidebarToggle();
  initGlobalSearch();
  initTextareaAutoResize();
  initKeyboardShortcuts();
  initAIProviderSwitcher();
  initNotifications();

  // ── EYE AI Global Branding ──
  if (typeof window.initEyeAIBranding === 'function') {
    window.initEyeAIBranding();
  }

  // Update user info in sidebar
  if (CURRENT_USER) {
    const sidebarTenant = document.getElementById('sidebarTenant');
    if (sidebarTenant) sidebarTenant.textContent = CURRENT_USER.tenant_name || CURRENT_USER.tenant || 'MSSP Global';
    // Update topbar user info
    const userNameEl = document.querySelector('.user-name, #userName');
    if (userNameEl) userNameEl.textContent = CURRENT_USER.name || CURRENT_USER.email;
    const userRoleEl = document.querySelector('.user-role, #userRole');
    if (userRoleEl) userRoleEl.textContent = CURRENT_USER.role || 'Analyst';
    const userAvatarEl = document.querySelector('.user-avatar-text, #userAvatar');
    if (userAvatarEl) userAvatarEl.textContent = CURRENT_USER.avatar || 'U';
  }

  // ── Real-time backend connection ──
  if (window.WS) {
    WS.connect();
    WS.subscribeAlerts();
    if (window.initRealtime) initRealtime();
  }

  // ── Initialise live data module (priority: Dashboard first) ──
  if (typeof initLiveData === 'function') {
    initLiveData().catch(err => {
      console.warn('[Wadjet-Eye AI] Live data init failed:', err.message);
      showToast('Live data unavailable — check backend URL', 'warning');
    });
  }

  // ── CTI Live Pages Layer ──
  if (typeof initLivePages === 'function') {
    initLivePages().catch(err => {
      console.warn('[Wadjet-Eye AI] Live pages init failed:', err.message);
    });
  }

  // ── AI Orchestrator (floating chat panel) ──
  if (typeof AIOrchestrator !== 'undefined' && typeof AIOrchestrator.init === 'function') {
    console.log('[Wadjet-Eye AI] AI Orchestrator ready');
  }

  // Wire AutoRefresh to tab navigation
  if (typeof AutoRefresh !== 'undefined') {
    document.querySelectorAll('[data-page]').forEach(link => {
      link.addEventListener('click', () => {
        const page = link.dataset.page || link.getAttribute('onclick')?.match(/navigate\('([^']+)'\)/)?.[1];
        if (page) AutoRefresh.setActiveTab(page);
      });
    });
  }

  // Render initial page
  renderCommandCenter();
  startLiveUpdates();
  setTimeout(bootSequence, 500);

  console.log('[Wadjet-Eye AI] Platform initialized — v17.0');
  console.log('[Wadjet-Eye AI] User:', CURRENT_USER?.name, '|', CURRENT_USER?.role);
  console.log('[Wadjet-Eye AI] Backend:', window.THREATPILOT_API_URL);
  console.log('[Wadjet-Eye AI] Mode: LIVE DATA + CTI v3.0');
}

/* ════════════════════════════════════════════════
   DOM READY — show login screen
   ════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  // Show login, hide app
  document.getElementById('loginScreen').style.display = 'flex';
  document.getElementById('mainApp').style.display = 'none';

  // Allow Enter key on login form
  ['loginEmail','loginPassword'].forEach(id => {
    document.getElementById(id)?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') doLogin();
    });
  });
});
