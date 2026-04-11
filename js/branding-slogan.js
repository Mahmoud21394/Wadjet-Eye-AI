/**
 * ══════════════════════════════════════════════════════════════════════════
 *  EYEbot AI — Animated Branding Slogan Component v5.1
 *  FILE: js/branding-slogan.js
 *
 *  Adds a cyber-style animated slogan to:
 *  1. The login screen header
 *  2. The main dashboard header bar
 *
 *  Features:
 *  ─────────
 *  • Typing/scanning effect for the slogan text
 *  • Cyber glow pulse animation (neon green/cyan)
 *  • Scanline sweep across the text
 *  • Matrix-style character scramble on first load
 *  • Responsive — collapses gracefully on mobile
 *
 *  Usage: auto-initializes when DOM is ready.
 * ══════════════════════════════════════════════════════════════════════════
 */
'use strict';

(function WadjetBranding() {

  const SLOGANS = [
    'Eye Detects Everything. AI Protects Everything.',
    'Real-Time Intelligence. Zero Compromise.',
    'Threat Hunting. Automated Response. Total Visibility.',
    'SOC Operations Powered by AI.',
  ];

  let currentSlogan = 0;
  const CHAR_POOL   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%&';

  /* ═══════════════════════════════════════
     CSS INJECTION
  ═══════════════════════════════════════ */
  const CSS = `
    /* ── Branding Slogan Styles ── */
    @keyframes wb-glow-pulse {
      0%, 100% { text-shadow: 0 0 6px #00ff88, 0 0 12px #00ff8866, 0 0 20px #00ff8833; }
      50%       { text-shadow: 0 0 12px #00ffcc, 0 0 24px #00ffcc88, 0 0 40px #00ffcc44; }
    }
    @keyframes wb-scanline {
      0%   { left: -100%; }
      100% { left: 120%;  }
    }
    @keyframes wb-cursor-blink {
      0%, 49% { opacity: 1; }
      50%, 100% { opacity: 0; }
    }
    @keyframes wb-fade-in {
      from { opacity: 0; transform: translateY(-6px); }
      to   { opacity: 1; transform: translateY(0); }
    }
    @keyframes wb-border-glow {
      0%, 100% { border-color: #00ff8844; box-shadow: 0 0 8px #00ff8822; }
      50%       { border-color: #00ffcc88; box-shadow: 0 0 16px #00ffcc44; }
    }

    .wb-slogan-wrap {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      position: relative;
      padding: 4px 14px 4px 10px;
      border: 1px solid #00ff8844;
      border-radius: 6px;
      background: linear-gradient(90deg, #00ff8808, #00ffcc05);
      overflow: hidden;
      animation: wb-border-glow 3s ease-in-out infinite;
      max-width: 100%;
    }

    .wb-slogan-icon {
      font-size: 0.85em;
      color: #00ff88;
      flex-shrink: 0;
      animation: wb-glow-pulse 2s ease-in-out infinite;
    }

    .wb-slogan-text {
      font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
      font-size: 0.78em;
      font-weight: 600;
      letter-spacing: 0.04em;
      color: #00ff88;
      animation: wb-glow-pulse 2s ease-in-out infinite;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .wb-cursor {
      display: inline-block;
      width: 2px;
      height: 1em;
      background: #00ff88;
      margin-left: 2px;
      vertical-align: text-bottom;
      animation: wb-cursor-blink 0.8s step-end infinite;
      box-shadow: 0 0 6px #00ff88;
    }

    .wb-scanline {
      position: absolute;
      top: 0;
      left: -100%;
      width: 40%;
      height: 100%;
      background: linear-gradient(90deg, transparent, #00ff8812, transparent);
      animation: wb-scanline 3s linear infinite;
      pointer-events: none;
    }

    /* ── Login screen large version ── */
    .wb-login-slogan-wrap {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      padding: 12px 20px;
      border: 1px solid #00ff8833;
      border-radius: 8px;
      background: linear-gradient(135deg, #00ff8808, #00ffcc05);
      overflow: hidden;
      position: relative;
      animation: wb-border-glow 3s ease-in-out infinite, wb-fade-in 0.8s ease forwards;
      margin: 12px 0;
    }

    .wb-login-slogan-text {
      font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
      font-size: 1.05em;
      font-weight: 700;
      letter-spacing: 0.06em;
      color: #00ff88;
      text-align: center;
      animation: wb-glow-pulse 2.5s ease-in-out infinite;
      line-height: 1.4;
    }

    .wb-login-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 2px 10px;
      border: 1px solid #00ff8844;
      border-radius: 20px;
      background: #00ff8810;
      font-size: 0.7em;
      font-weight: 600;
      color: #00ff88aa;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    /* Responsive */
    @media (max-width: 600px) {
      .wb-slogan-text { font-size: 0.68em; }
      .wb-login-slogan-text { font-size: 0.9em; }
    }
  `;

  function injectCSS() {
    if (document.getElementById('wb-branding-css')) return;
    const style = document.createElement('style');
    style.id = 'wb-branding-css';
    style.textContent = CSS;
    document.head.appendChild(style);
  }

  /* ═══════════════════════════════════════
     TYPING ANIMATION
  ═══════════════════════════════════════ */
  function typeText(el, text, speed = 40, onDone = null) {
    el.textContent = '';
    let i = 0;
    const timer = setInterval(() => {
      if (i < text.length) {
        el.textContent += text[i];
        i++;
      } else {
        clearInterval(timer);
        if (onDone) onDone();
      }
    }, speed);
    return timer;
  }

  /* ═══════════════════════════════════════
     MATRIX SCRAMBLE EFFECT
     (scrambles characters, then resolves to real text)
  ═══════════════════════════════════════ */
  function scrambleText(el, finalText, duration = 1200) {
    const steps  = Math.ceil(duration / 50);
    const chars  = finalText.split('');
    let   step   = 0;

    const revealByIndex = Math.ceil(chars.length / steps);

    const timer = setInterval(() => {
      step++;
      const revealed = Math.min(step * revealByIndex, chars.length);
      const scrambled = chars.map((c, i) => {
        if (i < revealed) return c;
        if (c === ' ') return ' ';
        return CHAR_POOL[Math.floor(Math.random() * CHAR_POOL.length)];
      });
      el.textContent = scrambled.join('');
      if (revealed >= chars.length) clearInterval(timer);
    }, 50);
  }

  /* ═══════════════════════════════════════
     HEADER SLOGAN (dashboard top bar)
  ═══════════════════════════════════════ */
  function mountHeaderSlogan() {
    // Find the header bar — try several selectors used across the codebase
    const targets = [
      document.getElementById('headerSlogan'),
      document.querySelector('.header-slogan-slot'),
      document.querySelector('.top-bar-right'),
      document.querySelector('.topbar-right'),
      document.querySelector('.header-actions'),
      document.querySelector('.navbar-brand'),
    ].filter(Boolean);

    if (targets.length === 0) {
      // Create and insert into the top navigation bar
      const topbar = document.querySelector('.topbar') || document.querySelector('header') || document.querySelector('.main-header');
      if (!topbar) return;

      const slot = document.createElement('div');
      slot.id = 'headerSlogan';
      slot.style.cssText = 'display:flex;align-items:center;gap:8px;flex:1;justify-content:center;';
      topbar.appendChild(slot);
      targets.push(slot);
    }

    targets.forEach(target => {
      if (target.dataset.wbMounted) return;
      target.dataset.wbMounted = '1';

      const wrap = document.createElement('div');
      wrap.className = 'wb-slogan-wrap';
      wrap.innerHTML = `
        <i class="fas fa-eye wb-slogan-icon"></i>
        <span class="wb-slogan-text"></span>
        <span class="wb-cursor"></span>
        <div class="wb-scanline"></div>
      `;
      target.appendChild(wrap);

      const textEl = wrap.querySelector('.wb-slogan-text');
      let cycleTimer = null;

      function showSlogan(idx) {
        const text = SLOGANS[idx % SLOGANS.length];
        scrambleText(textEl, text, 1000);

        // After 6s, fade out and show next slogan
        clearTimeout(cycleTimer);
        cycleTimer = setTimeout(() => {
          textEl.style.opacity = '0';
          textEl.style.transition = 'opacity 0.4s';
          setTimeout(() => {
            textEl.style.opacity = '1';
            textEl.style.transition = 'opacity 0.4s';
            showSlogan(idx + 1);
          }, 500);
        }, 7000);
      }

      showSlogan(currentSlogan);
    });
  }

  /* ═══════════════════════════════════════
     LOGIN SCREEN SLOGAN
  ═══════════════════════════════════════ */
  function mountLoginSlogan() {
    const loginPanel = document.querySelector('.login-panel')
      || document.querySelector('.login-card')
      || document.querySelector('.login-box')
      || document.getElementById('loginScreen');

    if (!loginPanel) return;

    // Find logo/title area
    const logoArea = loginPanel.querySelector('.login-logo')
      || loginPanel.querySelector('.login-title-wrap')
      || loginPanel.querySelector('.login-header')
      || loginPanel.querySelector('h1')
      || loginPanel.querySelector('h2');

    if (!logoArea) return;

    // Check if already mounted
    if (document.getElementById('wb-login-slogan')) return;

    const wrap = document.createElement('div');
    wrap.id = 'wb-login-slogan';
    wrap.className = 'wb-login-slogan-wrap';
    wrap.innerHTML = `
      <div class="wb-login-badge">
        <i class="fas fa-shield-alt"></i>
        <span>Enterprise SOC Platform</span>
      </div>
      <div class="wb-login-slogan-text"></div>
      <div class="wb-scanline"></div>
    `;

    // Insert after logo area
    logoArea.insertAdjacentElement('afterend', wrap);

    const textEl = wrap.querySelector('.wb-login-slogan-text');
    let sloganIdx = 0;

    function cycleLoginSlogan() {
      const text = SLOGANS[sloganIdx % SLOGANS.length];
      typeText(textEl, text, 55, () => {
        setTimeout(() => {
          // Backspace effect
          const deleteTimer = setInterval(() => {
            if (textEl.textContent.length > 0) {
              textEl.textContent = textEl.textContent.slice(0, -1);
            } else {
              clearInterval(deleteTimer);
              sloganIdx++;
              setTimeout(cycleLoginSlogan, 400);
            }
          }, 30);
        }, 3500);
      });
    }

    cycleLoginSlogan();
  }

  /* ═══════════════════════════════════════
     INITIALIZATION
  ═══════════════════════════════════════ */
  function init() {
    injectCSS();

    // Mount in login screen immediately
    mountLoginSlogan();

    // Mount in dashboard header when app becomes visible
    const observer = new MutationObserver(() => {
      const mainApp = document.getElementById('mainApp');
      if (mainApp && mainApp.style.display !== 'none') {
        mountHeaderSlogan();
      }
    });

    observer.observe(document.body, { subtree: true, attributes: true, attributeFilter: ['style'] });

    // Also try immediately in case already visible
    const mainApp = document.getElementById('mainApp');
    if (mainApp && mainApp.style.display !== 'none') {
      mountHeaderSlogan();
    }
  }

  /* ═══════════════════════════════════════
     PUBLIC API
  ═══════════════════════════════════════ */
  window.WadjetBranding = {
    init,
    mountHeaderSlogan,
    mountLoginSlogan,
    setSlogans(arr) {
      if (Array.isArray(arr) && arr.length) SLOGANS.splice(0, SLOGANS.length, ...arr);
    },
  };

  // Auto-init
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    // DOM already ready — slight delay to let other scripts run first
    setTimeout(init, 100);
  }

})();
