/* ═══════════════════════════════════════════════════════════════════
   Wadjet-Eye AI — Advanced Login Page v20.0
   Production-grade SOC-style login with:
   - Animated cyber grid + scan-line background
   - Glassmorphism login card
   - Typing effect tagline
   - Floating particles
   - Threat Intelligence widget (left panel)
   - AI Insight panel (right panel)
   - MFA toggle
   - Gradient button with ripple + loading state
   - Security badges footer
   - Responsive 3-column layout
   ═══════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  /* ────────────────────────────────────────────────
     LIVE THREAT DATA (rotated automatically)
  ──────────────────────────────────────────────── */
  const THREAT_INTEL = [
    {
      name: 'LockBit 4.0 RaaS Campaign',
      severity: 'CRITICAL',
      region: 'North America',
      sector: 'Healthcare / Finance',
      iocs: 47,
      score: 94,
      color: '#ef4444'
    },
    {
      name: 'APT29 — SVR Espionage Wave',
      severity: 'HIGH',
      region: 'Europe / NATO',
      sector: 'Government / Defense',
      iocs: 33,
      score: 87,
      color: '#f97316'
    },
    {
      name: 'BlackCat ALPHV — Supply Chain',
      severity: 'CRITICAL',
      region: 'Global',
      sector: 'Manufacturing / Legal',
      iocs: 61,
      score: 92,
      color: '#ef4444'
    },
    {
      name: 'Lazarus Group — Crypto Theft',
      severity: 'HIGH',
      region: 'Asia Pacific',
      sector: 'Finance / Crypto',
      iocs: 28,
      score: 81,
      color: '#f59e0b'
    }
  ];

  const AI_INSIGHTS = [
    {
      summary: 'Detected coordinated ransomware deployment across 3 healthcare tenants. Lateral movement via SMB exploitation observed. Recommend immediate network segmentation.',
      recommendation: 'Isolate affected segments, rotate credentials, deploy Sigma rule HIT-2025-0214 across all SIEM instances.',
      tags: ['Ransomware', 'SMB', 'Healthcare', 'Sigma']
    },
    {
      summary: 'Phishing campaign leveraging CVE-2025-1847 impersonating Microsoft365 login pages. 14 credential submissions detected from tenant subdomains.',
      recommendation: 'Enforce conditional access policies, revoke compromised sessions, deploy anti-phishing DNS sinkholes.',
      tags: ['Phishing', 'CVE-2025-1847', 'M365', 'DNS']
    },
    {
      summary: 'Supply chain compromise in popular npm package "fast-xml-parser" v4.3.x. Malicious code exfiltrates environment variables on import.',
      recommendation: 'Pin dependencies, audit package.json files, run supply chain SBOM scan across all development environments.',
      tags: ['Supply Chain', 'npm', 'SBOM', 'Exfiltration']
    }
  ];

  const ACTIVE_ALERTS = [
    { text: 'New IOC cluster detected — 12 malicious IPs blocked', time: '2m ago', color: '#ef4444' },
    { text: 'LockBit 4.0 victim site updated — 3 new entries', time: '8m ago', color: '#f97316' },
    { text: 'CVE-2025-0284 CVSS 9.8 — Patch advisory issued', time: '15m ago', color: '#a855f7' },
    { text: 'AbuseIPDB: 847 IPs flagged in last 24h', time: '31m ago', color: '#22c55e' }
  ];

  const TYPING_PHRASES = [
    'AI-Agentic Cyber Threat Intelligence...',
    'Real-time IOC enrichment & analysis...',
    'Multi-tenant SOC operations platform...',
    'Powered by GPT-4o + Claude + Gemini...'
  ];

  /* ────────────────────────────────────────────────
     BUILD THE LOGIN PAGE
  ──────────────────────────────────────────────── */
  function buildLoginV20() {
    const loginScreen = document.getElementById('loginScreen');
    if (!loginScreen) return;

    const threatData = THREAT_INTEL[Math.floor(Math.random() * THREAT_INTEL.length)];
    const aiData = AI_INSIGHTS[Math.floor(Math.random() * AI_INSIGHTS.length)];

    loginScreen.className = 'login-screen-v20';
    loginScreen.innerHTML = `
      <!-- Background layers -->
      <div class="lv20-bg-grid"></div>
      <div class="lv20-bg-fog"></div>
      <div class="lv20-scanline"></div>
      <div class="lv20-particles" id="lv20Particles"></div>

      <!-- 3-column layout -->
      <div class="lv20-layout">

        <!-- ══ LEFT: Threat Intelligence Widget ══ -->
        <div class="lv20-left-panel">

          <!-- Active Threat Widget -->
          <div class="lv20-threat-widget">
            <div class="lv20-widget-header">
              <div class="lv20-widget-dot"></div>
              <div class="lv20-widget-title">🔴 Active Threat Campaign</div>
            </div>

            <div class="lv20-threat-badge">
              <i class="fas fa-circle" style="font-size:7px;"></i>
              ${threatData.severity}
            </div>

            <div class="lv20-threat-name">${threatData.name}</div>

            <div class="lv20-threat-meta">
              <div class="lv20-meta-item">
                <div class="lv20-meta-label">Target Region</div>
                <div class="lv20-meta-value" style="font-size:11px;">${threatData.region}</div>
              </div>
              <div class="lv20-meta-item">
                <div class="lv20-meta-label">Sector</div>
                <div class="lv20-meta-value" style="font-size:11px;">${threatData.sector}</div>
              </div>
              <div class="lv20-meta-item">
                <div class="lv20-meta-label">Active IOCs</div>
                <div class="lv20-meta-value" style="color:${threatData.color}">${threatData.iocs}</div>
              </div>
              <div class="lv20-meta-item">
                <div class="lv20-meta-label">Threat Score</div>
                <div class="lv20-meta-value" style="color:${threatData.color}">${threatData.score}/100</div>
              </div>
            </div>

            <div class="lv20-threat-bar">
              <div class="lv20-threat-bar-label">
                <span>Threat Level</span>
                <span style="color:${threatData.color}">${threatData.score}%</span>
              </div>
              <div class="lv20-bar-track">
                <div class="lv20-bar-fill" style="width:${threatData.score}%;background:linear-gradient(90deg,${threatData.color},${threatData.color}aa);"></div>
              </div>
            </div>
          </div>

          <!-- Active Threats Counter -->
          <div class="lv20-active-threats">
            <div class="lv20-at-header">
              <i class="fas fa-shield-virus"></i>
              Platform Status
            </div>
            <div class="lv20-at-grid">
              <div class="lv20-at-cell">
                <div class="lv20-at-num" style="color:#ef4444;" id="lv20-cnt-critical">0</div>
                <div class="lv20-at-type">Critical</div>
              </div>
              <div class="lv20-at-cell">
                <div class="lv20-at-num" style="color:#f97316;" id="lv20-cnt-iocs">0</div>
                <div class="lv20-at-type">Live IOCs</div>
              </div>
              <div class="lv20-at-cell">
                <div class="lv20-at-num" style="color:#a855f7;" id="lv20-cnt-actors">0</div>
                <div class="lv20-at-type">Actors</div>
              </div>
              <div class="lv20-at-cell">
                <div class="lv20-at-num" style="color:#22c55e;" id="lv20-cnt-tenants">0</div>
                <div class="lv20-at-type">Tenants</div>
              </div>
            </div>
          </div>

        </div>

        <!-- ══ CENTER: Login Card ══ -->
        <div class="lv20-card" id="lv20LoginCard">

          <!-- Logo -->
          <div class="lv20-logo">
            <div class="lv20-logo-img-wrap">
              <div class="lv20-logo-ring"></div>
              <img src="images/wadjet-logo.png" alt="Wadjet-Eye AI" class="lv20-logo-img" onerror="this.style.display='none'"/>
            </div>
            <div class="lv20-logo-name">Wadjet-Eye AI</div>
            <div class="lv20-logo-tagline">Cyber Threat Intelligence Platform v20.0</div>
          </div>

          <!-- Typing effect -->
          <div class="lv20-typing-wrap">
            <span id="lv20TypeText"></span><span class="lv20-cursor"></span>
          </div>

          <!-- Error display -->
          <div id="lv20Error" style="display:none;" class="lv20-error">
            <i class="fas fa-exclamation-circle"></i>
            <span id="lv20ErrorText">Authentication failed.</span>
          </div>

          <!-- Tenant -->
          <div class="lv20-field">
            <label class="lv20-label"><i class="fas fa-building"></i>Tenant</label>
            <div class="lv20-input-wrap">
              <i class="lv20-input-icon fas fa-building"></i>
              <select id="loginTenant" class="lv20-select" style="padding-right:16px;">
                <option value="mssp-global">MSSP Global Operations</option>
                <option value="hackerone">HackerOne Security Team</option>
                <option value="bugcrowd">Bugcrowd Platform</option>
                <option value="enterprise">Enterprise</option>
              </select>
            </div>
          </div>

          <!-- Email -->
          <div class="lv20-field">
            <label class="lv20-label"><i class="fas fa-envelope"></i>Email Address</label>
            <div class="lv20-input-wrap">
              <i class="lv20-input-icon fas fa-envelope"></i>
              <input type="email" id="loginEmail" class="lv20-input"
                placeholder="analyst@company.com"
                autocomplete="email"
                onkeydown="if(event.key==='Enter')document.getElementById('loginPassword').focus()" />
              <div class="lv20-focus-line"></div>
            </div>
          </div>

          <!-- Password -->
          <div class="lv20-field">
            <label class="lv20-label"><i class="fas fa-lock"></i>Password</label>
            <div class="lv20-input-wrap">
              <i class="lv20-input-icon fas fa-lock"></i>
              <input type="password" id="loginPassword" class="lv20-input"
                placeholder="••••••••"
                autocomplete="current-password"
                onkeydown="if(event.key==='Enter')doLogin()" />
              <button type="button" class="lv20-eye-toggle" id="lv20EyeToggle" onclick="_lv20ToggleEye()" title="Show/hide password">
                <i class="fas fa-eye" id="lv20EyeIcon"></i>
              </button>
              <div class="lv20-focus-line"></div>
            </div>
          </div>

          <!-- MFA Toggle -->
          <div class="lv20-mfa-row">
            <div class="lv20-mfa-info">
              <div class="lv20-mfa-icon">
                <i class="fas fa-shield-alt"></i>
              </div>
              <div>
                <div class="lv20-mfa-label">Multi-Factor Authentication</div>
                <div class="lv20-mfa-sub">TOTP / Authenticator app</div>
              </div>
            </div>
            <label class="lv20-toggle">
              <input type="checkbox" id="mfaToggleV20" checked />
              <span class="lv20-toggle-slider"></span>
            </label>
          </div>

          <!-- Login Button -->
          <button class="lv20-btn" id="loginBtn" onclick="doLogin()">
            <i class="fas fa-eye"></i>
            Authenticate Securely
          </button>

          <!-- Security Badges -->
          <div class="lv20-security-badges">
            <div class="lv20-badge">
              <i class="fas fa-lock"></i>
              TLS 1.3
            </div>
            <div class="lv20-badge">
              <i class="fas fa-user-shield"></i>
              Zero Trust
            </div>
            <div class="lv20-badge">
              <i class="fas fa-certificate"></i>
              SOC2
            </div>
            <div class="lv20-badge">
              <i class="fas fa-shield-virus"></i>
              ISO 27001
            </div>
          </div>
        </div>

        <!-- ══ RIGHT: AI Insight Panel ══ -->
        <div class="lv20-right-panel">

          <!-- AI Insight -->
          <div class="lv20-ai-panel">
            <div class="lv20-ai-header">
              <div class="lv20-ai-icon">
                <i class="fas fa-robot"></i>
              </div>
              <div>
                <div class="lv20-ai-title">AI Threat Insight</div>
                <div class="lv20-ai-subtitle">Real-time analysis</div>
              </div>
            </div>

            <div class="lv20-ai-summary">${aiData.summary}</div>

            <div class="lv20-ai-recommendation">
              <strong>⚡ Recommended Action</strong>
              ${aiData.recommendation}
            </div>

            <div class="lv20-ai-tags">
              ${aiData.tags.map(t => `<span class="lv20-ai-tag">#${t}</span>`).join('')}
            </div>
          </div>

          <!-- Recent Alerts -->
          <div class="lv20-alerts-widget">
            <div class="lv20-alerts-title">
              <i class="fas fa-bell" style="animation:lv20-blink 1.5s ease-in-out infinite;"></i>
              Recent Alerts
            </div>
            ${ACTIVE_ALERTS.map((a, i) => `
              <div class="lv20-alert-item" style="animation-delay:${i * 0.1}s">
                <div class="lv20-alert-dot" style="background:${a.color};box-shadow:0 0 6px ${a.color};"></div>
                <div class="lv20-alert-text">${a.text}</div>
                <div class="lv20-alert-time">${a.time}</div>
              </div>
            `).join('')}
          </div>

        </div>

      </div><!-- end lv20-layout -->

      <div class="lv20-version-tag">EYEBOT AI v20.0 · SOC PLATFORM · SECURE SESSION</div>
    `;

    // Initialize effects
    _lv20SpawnParticles();
    _lv20StartTyping();
    _lv20AnimateCounters();

    // Sync the old mfaToggle selector references (main.js looks for mfaToggle)
    _lv20SyncMFA();

    // Rotate threat data every 12 seconds
    setInterval(_lv20RotateThreat, 12000);

    // Add keyboard shortcut
    document.addEventListener('keydown', function(e) {
      if (e.ctrlKey && e.key === 'k') {
        const emailEl = document.getElementById('loginEmail');
        if (emailEl) emailEl.focus();
        e.preventDefault();
      }
    }, { once: true });
  }

  /* ────────────────────────────────────────────────
     PARTICLES
  ──────────────────────────────────────────────── */
  function _lv20SpawnParticles() {
    const container = document.getElementById('lv20Particles');
    if (!container) return;
    const count = 40;
    const colors = ['#00d4ff', '#3b82f6', '#a855f7', '#22c55e'];

    for (let i = 0; i < count; i++) {
      const p = document.createElement('div');
      p.className = 'lv20-particle';
      const color = colors[Math.floor(Math.random() * colors.length)];
      p.style.cssText = `
        left:${Math.random() * 100}%;
        top:${Math.random() * 100}%;
        background:${color};
        box-shadow:0 0 6px ${color};
        --dur:${5 + Math.random() * 10}s;
        --delay:${Math.random() * 5}s;
        --op:${0.2 + Math.random() * 0.6};
        width:${1 + Math.random() * 3}px;
        height:${1 + Math.random() * 3}px;
      `;
      container.appendChild(p);
    }
  }

  /* ────────────────────────────────────────────────
     TYPING EFFECT
  ──────────────────────────────────────────────── */
  let _typingIdx = 0;
  let _typingCharIdx = 0;
  let _typingDeleting = false;
  let _typingTimer = null;

  function _lv20StartTyping() {
    const el = document.getElementById('lv20TypeText');
    if (!el) return;

    function tick() {
      const phrase = TYPING_PHRASES[_typingIdx % TYPING_PHRASES.length];
      if (!_typingDeleting) {
        el.textContent = phrase.slice(0, ++_typingCharIdx);
        if (_typingCharIdx >= phrase.length) {
          _typingDeleting = true;
          _typingTimer = setTimeout(tick, 2200);
          return;
        }
      } else {
        el.textContent = phrase.slice(0, --_typingCharIdx);
        if (_typingCharIdx === 0) {
          _typingDeleting = false;
          _typingIdx++;
          _typingTimer = setTimeout(tick, 300);
          return;
        }
      }
      _typingTimer = setTimeout(tick, _typingDeleting ? 40 : 65);
    }
    tick();
  }

  /* ────────────────────────────────────────────────
     COUNTER ANIMATIONS
  ──────────────────────────────────────────────── */
  function _lv20AnimateCounters() {
    const targets = {
      'lv20-cnt-critical': 23,
      'lv20-cnt-iocs':     1847,
      'lv20-cnt-actors':   94,
      'lv20-cnt-tenants':  12
    };

    Object.entries(targets).forEach(([id, target]) => {
      const el = document.getElementById(id);
      if (!el) return;
      let current = 0;
      const increment = Math.ceil(target / 40);
      const delay = Math.random() * 400;

      setTimeout(() => {
        const timer = setInterval(() => {
          current = Math.min(current + increment, target);
          el.textContent = current.toLocaleString();
          if (current >= target) clearInterval(timer);
        }, 40);
      }, delay);
    });
  }

  /* ────────────────────────────────────────────────
     THREAT DATA ROTATION
  ──────────────────────────────────────────────── */
  let _threatIdx = 0;

  function _lv20RotateThreat() {
    _threatIdx = (_threatIdx + 1) % THREAT_INTEL.length;
    const d = THREAT_INTEL[_threatIdx];
    const widget = document.querySelector('.lv20-threat-widget');
    if (!widget) return;

    widget.style.opacity = '0';
    widget.style.transition = 'opacity 0.3s ease';

    setTimeout(() => {
      const nameEl  = widget.querySelector('.lv20-threat-name');
      const badgeEl = widget.querySelector('.lv20-threat-badge');
      const fill    = widget.querySelector('.lv20-bar-fill');
      const score   = widget.querySelector('.lv20-threat-bar-label span:last-child');
      const iocEl   = document.getElementById('lv20-cnt-ioc-meta');

      if (nameEl)  nameEl.textContent = d.name;
      if (badgeEl) {
        badgeEl.innerHTML = `<i class="fas fa-circle" style="font-size:7px;"></i> ${d.severity}`;
      }
      if (fill) {
        fill.style.width = d.score + '%';
        fill.style.background = `linear-gradient(90deg,${d.color},${d.color}aa)`;
      }
      if (score) {
        score.textContent = d.score + '%';
        score.style.color = d.color;
      }

      widget.style.opacity = '1';
    }, 300);
  }

  /* ────────────────────────────────────────────────
     PASSWORD EYE TOGGLE
  ──────────────────────────────────────────────── */
  window._lv20ToggleEye = function () {
    const pwEl   = document.getElementById('loginPassword');
    const iconEl = document.getElementById('lv20EyeIcon');
    if (!pwEl || !iconEl) return;
    const show = pwEl.type === 'password';
    pwEl.type = show ? 'text' : 'password';
    iconEl.className = show ? 'fas fa-eye-slash' : 'fas fa-eye';
  };

  /* ────────────────────────────────────────────────
     MFA SYNC — keep old toggle working
  ──────────────────────────────────────────────── */
  function _lv20SyncMFA() {
    // Create hidden legacy toggle if missing (some old code references it)
    if (!document.getElementById('mfaToggle')) {
      const legacyToggle = document.createElement('div');
      legacyToggle.id = 'mfaToggle';
      legacyToggle.className = 'toggle-switch on';
      legacyToggle.style.display = 'none';
      document.body.appendChild(legacyToggle);
    }
    // Sync v20 checkbox → legacy
    const v20Chk = document.getElementById('mfaToggleV20');
    if (v20Chk) {
      v20Chk.addEventListener('change', function () {
        const legacyEl = document.getElementById('mfaToggle');
        if (!legacyEl) return;
        if (v20Chk.checked) legacyEl.classList.add('on');
        else legacyEl.classList.remove('on');
      });
    }
  }

  /* ────────────────────────────────────────────────
     LOGIN BUTTON STATE MANAGEMENT
     Patches the existing doLogin() to use v20 UI
  ──────────────────────────────────────────────── */
  function _patchLoginBtn() {
    // Override the loginBtn loading state visuals
    const origDoLogin = window.doLogin;
    if (!origDoLogin) return;

    window.doLogin = async function () {
      const btn   = document.getElementById('loginBtn');
      const errEl = document.getElementById('lv20Error');
      const errTx = document.getElementById('lv20ErrorText');
      const card  = document.getElementById('lv20LoginCard');

      // Clear old error
      if (errEl) errEl.style.display = 'none';

      // Loading state
      if (btn) {
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Authenticating…';
        btn.disabled = true;
        btn.classList.add('loading');
      }

      // Intercept showError to use lv20 error box
      const origErrEl = document.getElementById('loginError');
      if (origErrEl) {
        origErrEl.style.display = 'none'; // hide old error box
        // Mirror text into v20 error box
        const obs = new MutationObserver(() => {
          if (origErrEl.style.display !== 'none' && origErrEl.textContent) {
            if (errEl && errTx) {
              errTx.textContent = origErrEl.textContent.replace(/^⚠️\s*/, '');
              errEl.style.display = 'flex';
              errEl.style.animation = 'none';
              void errEl.offsetWidth;
              errEl.style.animation = '';
            }
            origErrEl.style.display = 'none';
          }
        });
        obs.observe(origErrEl, { attributes: true, childList: true });
        setTimeout(() => obs.disconnect(), 10000);
      }

      try {
        await origDoLogin.call(this);

        // On success — add success state
        if (card) {
          card.classList.add('auth-success');
        }
      } catch (err) {
        console.error('[LoginV20] doLogin error:', err);
      } finally {
        // Restore button if still visible
        if (btn && document.getElementById('loginScreen')) {
          btn.innerHTML = '<i class="fas fa-eye"></i> Authenticate Securely';
          btn.disabled = false;
          btn.classList.remove('loading');
        }
      }
    };
  }

  /* ────────────────────────────────────────────────
     INIT
  ──────────────────────────────────────────────── */
  function _init() {
    // Inject CSS link if not present
    if (!document.getElementById('lv20CssLink')) {
      const link = document.createElement('link');
      link.id   = 'lv20CssLink';
      link.rel  = 'stylesheet';
      link.href = 'css/login-v20.css';
      document.head.appendChild(link);
    }

    // Build login page
    buildLoginV20();

    // Patch login button after doLogin is available
    const _waitForLogin = setInterval(() => {
      if (typeof window.doLogin === 'function') {
        clearInterval(_waitForLogin);
        _patchLoginBtn();
      }
    }, 100);
  }

  // Run after DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _init);
  } else {
    // DOM already ready — run now
    _init();
  }

})();
