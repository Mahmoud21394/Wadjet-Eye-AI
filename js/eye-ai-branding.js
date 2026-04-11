/**
 * ══════════════════════════════════════════════════════════
 *  EYEbot AI — "EYEbot AI" Global Branding Module v1.0
 *  Applies the icon/logo globally across:
 *    • Login screen
 *    • Navbar / sidebar header
 *    • Dashboard footer bar
 *    • Page titles and favicons
 *    • Report headers
 * ══════════════════════════════════════════════════════════
 */
'use strict';

/* ─────────────────────────────────────────────
   BRANDING CONSTANTS
───────────────────────────────────────────── */
const EYE_AI_BRAND = {
  name:       'EYEbot AI',
  shortName:  'EYEbot AI',
  tagline:    'AI-Agentic Cyber Threat Intelligence Platform',
  version:    'v17.0',
  logoPath:   'images/wadjet-logo.png',
  primaryColor: '#1d6ae5',
  accentColor:  '#c9a227',
  // Inline SVG eye icon as fallback
  svgIcon: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" fill="none">
    <circle cx="24" cy="24" r="22" fill="#0d1117" stroke="#1d6ae5" stroke-width="2"/>
    <ellipse cx="24" cy="24" rx="14" ry="9" stroke="#c9a227" stroke-width="1.5" fill="none"/>
    <circle cx="24" cy="24" r="5" fill="#1d6ae5"/>
    <circle cx="24" cy="24" r="2.5" fill="#c9a227"/>
    <circle cx="22" cy="22" r="1" fill="white" opacity="0.7"/>
    <line x1="24" y1="4" x2="24" y2="8" stroke="#1d6ae5" stroke-width="1.5" stroke-linecap="round"/>
    <line x1="24" y1="40" x2="24" y2="44" stroke="#1d6ae5" stroke-width="1.5" stroke-linecap="round"/>
    <line x1="4" y1="24" x2="8" y2="24" stroke="#1d6ae5" stroke-width="1.5" stroke-linecap="round"/>
    <line x1="40" y1="24" x2="44" y2="24" stroke="#1d6ae5" stroke-width="1.5" stroke-linecap="round"/>
  </svg>`,
};

/* ─────────────────────────────────────────────
   INIT — runs after DOM is ready
───────────────────────────────────────────── */
function initEyeAIBranding() {
  _applyFaviconBranding();
  _applyLoginBranding();
  _applySidebarBranding();
  _applyTopbarBranding();
  _injectFooterBar();
  _applyPageTitleBranding();
  console.info('[EYEbot AI Branding] ✅ Applied globally');
}

/* ─────────────────────────────────────────────
   FAVICON
───────────────────────────────────────────── */
function _applyFaviconBranding() {
  const link = document.querySelector("link[rel='icon']") || document.createElement('link');
  link.rel  = 'icon';
  link.type = 'image/png';
  link.href = EYE_AI_BRAND.logoPath;
  if (!link.parentNode) document.head.appendChild(link);

  // Apple touch icon
  const apple = document.querySelector("link[rel='apple-touch-icon']") || document.createElement('link');
  apple.rel  = 'apple-touch-icon';
  apple.href = EYE_AI_BRAND.logoPath;
  if (!apple.parentNode) document.head.appendChild(apple);
}

/* ─────────────────────────────────────────────
   PAGE TITLE
───────────────────────────────────────────── */
function _applyPageTitleBranding() {
  document.title = `${EYE_AI_BRAND.name} — ${EYE_AI_BRAND.tagline}`;
}

/* ─────────────────────────────────────────────
   LOGIN SCREEN
───────────────────────────────────────────── */
function _applyLoginBranding() {
  const loginLogo = document.querySelector('.login-logo-img');
  if (loginLogo) {
    loginLogo.src = EYE_AI_BRAND.logoPath;
    loginLogo.alt = EYE_AI_BRAND.name;
    loginLogo.style.cssText = `
      width:72px;height:72px;object-fit:contain;border-radius:16px;
      border:1.5px solid ${EYE_AI_BRAND.primaryColor}44;
      box-shadow:0 0 32px ${EYE_AI_BRAND.primaryColor}22,0 0 8px ${EYE_AI_BRAND.accentColor}11;
    `;
  }

  const logoName = document.querySelector('.login-logo-name');
  if (logoName) {
    logoName.textContent = EYE_AI_BRAND.name;
    logoName.style.cssText = `
      font-size:1.35em;font-weight:800;letter-spacing:-.01em;
      background:linear-gradient(135deg,${EYE_AI_BRAND.primaryColor},${EYE_AI_BRAND.accentColor});
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
    `;
  }

  const logoTagline = document.querySelector('.login-logo-tagline');
  if (logoTagline) {
    logoTagline.textContent = EYE_AI_BRAND.tagline + ' ' + EYE_AI_BRAND.version;
    logoTagline.style.cssText = `
      font-size:.7em;color:#8b949e;margin-top:3px;letter-spacing:.02em;
    `;
  }

  // Enhance the eye-blink animation on login screen
  const loginCard = document.querySelector('.login-card');
  if (loginCard) {
    loginCard.style.cssText += `
      background:rgba(13,17,23,.96);
      border:1px solid rgba(29,106,229,.18);
      box-shadow:0 24px 80px rgba(0,0,0,.7),0 0 60px rgba(29,106,229,.06),inset 0 0 40px rgba(29,106,229,.02);
    `;
  }

  // Add floating eye particles to login background
  _addLoginEyeParticles();
}

function _addLoginEyeParticles() {
  const particles = document.getElementById('loginParticles');
  if (!particles) return;
  particles.innerHTML = '';
  const count = 12;
  for (let i = 0; i < count; i++) {
    const el = document.createElement('div');
    const size = 4 + Math.random() * 8;
    const x    = Math.random() * 100;
    const y    = Math.random() * 100;
    const dur  = 4 + Math.random() * 6;
    const del  = Math.random() * 4;
    const opacity = 0.03 + Math.random() * 0.08;
    el.style.cssText = `
      position:absolute;left:${x}%;top:${y}%;
      width:${size}px;height:${size}px;
      background:radial-gradient(circle,${EYE_AI_BRAND.primaryColor},transparent);
      border-radius:50%;opacity:${opacity};
      animation:eyeFloat ${dur}s ease-in-out ${del}s infinite alternate;
      pointer-events:none;
    `;
    particles.appendChild(el);
  }

  // Add CSS keyframes if not already present
  if (!document.getElementById('eye-ai-keyframes')) {
    const style = document.createElement('style');
    style.id = 'eye-ai-keyframes';
    style.textContent = `
      @keyframes eyeFloat {
        0%   { transform:translateY(0) scale(1); opacity:.04; }
        50%  { transform:translateY(-20px) scale(1.2); opacity:.12; }
        100% { transform:translateY(-40px) scale(.8); opacity:.02; }
      }
      @keyframes eyePulseGlow {
        0%,100% { box-shadow:0 0 20px ${EYE_AI_BRAND.primaryColor}22; }
        50%      { box-shadow:0 0 40px ${EYE_AI_BRAND.primaryColor}44,0 0 80px ${EYE_AI_BRAND.primaryColor}11; }
      }
      @keyframes eyeScan {
        0%   { transform:scaleX(1); }
        50%  { transform:scaleX(0.8); opacity:.7; }
        100% { transform:scaleX(1); }
      }
      .eye-ai-logo-pulse { animation:eyePulseGlow 3s ease-in-out infinite; }
      .eye-ai-scan       { animation:eyeScan 2.5s ease-in-out infinite; }
    `;
    document.head.appendChild(style);
  }

  // Add pulse to logo image
  const loginLogo = document.querySelector('.login-logo-img');
  if (loginLogo) loginLogo.classList.add('eye-ai-logo-pulse');
}

/* ─────────────────────────────────────────────
   SIDEBAR HEADER
───────────────────────────────────────────── */
function _applySidebarBranding() {
  const sidebarImg = document.querySelector('.sidebar-logo-img');
  if (sidebarImg) {
    sidebarImg.src = EYE_AI_BRAND.logoPath;
    sidebarImg.alt = EYE_AI_BRAND.name;
    sidebarImg.style.cssText = `
      width:30px;height:30px;object-fit:contain;border-radius:7px;
      border:1px solid ${EYE_AI_BRAND.primaryColor}33;
    `;
  }

  const logoName = document.querySelector('.logo-name');
  if (logoName) {
    logoName.textContent = EYE_AI_BRAND.name;
    logoName.style.cssText = `
      font-size:.9em;font-weight:700;
      background:linear-gradient(135deg,${EYE_AI_BRAND.primaryColor},${EYE_AI_BRAND.accentColor});
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
      display:block;
    `;
  }
}

/* ─────────────────────────────────────────────
   TOP BAR
───────────────────────────────────────────── */
function _applyTopbarBranding() {
  // Find the top bar brand area — inject if needed
  const topbar = document.querySelector('.topbar') || document.querySelector('#topBar');
  if (!topbar) return;

  // Look for existing brand logo in topbar
  let brand = topbar.querySelector('.topbar-brand');
  if (!brand) {
    brand = document.createElement('div');
    brand.className = 'topbar-brand';
    brand.style.cssText = 'display:flex;align-items:center;gap:8px;margin-right:16px';
    topbar.insertBefore(brand, topbar.firstChild);
  }

  brand.innerHTML = `
    <img src="${EYE_AI_BRAND.logoPath}" alt="${EYE_AI_BRAND.name}"
      style="width:22px;height:22px;object-fit:contain;border-radius:5px;border:1px solid ${EYE_AI_BRAND.primaryColor}33"/>
    <span style="font-size:.78em;font-weight:700;color:#8b949e;letter-spacing:.04em">${EYE_AI_BRAND.shortName}</span>
  `;
}

/* ─────────────────────────────────────────────
   FOOTER BAR (injected into main app)
───────────────────────────────────────────── */
function _injectFooterBar() {
  // Remove existing footer if present
  const existing = document.getElementById('eyeAIFooter');
  if (existing) existing.remove();

  const footer = document.createElement('div');
  footer.id = 'eyeAIFooter';
  footer.style.cssText = `
    position:fixed;bottom:0;left:0;right:0;height:26px;
    background:rgba(8,12,20,.97);
    border-top:1px solid rgba(29,106,229,.15);
    display:flex;align-items:center;justify-content:space-between;
    padding:0 20px;z-index:100;
    backdrop-filter:blur(8px);
    font-size:.67em;color:#555;
    font-family:'JetBrains Mono',monospace;
  `;

  footer.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px">
      <img src="${EYE_AI_BRAND.logoPath}" alt="${EYE_AI_BRAND.name}" style="width:14px;height:14px;object-fit:contain;opacity:.6"/>
      <span style="color:#444">${EYE_AI_BRAND.name} ${EYE_AI_BRAND.version}</span>
      <span style="color:#333">·</span>
      <span style="color:#2d6aa0">${EYE_AI_BRAND.tagline}</span>
    </div>
    <div style="display:flex;align-items:center;gap:14px">
      <span id="footer-time" style="color:#333">${new Date().toLocaleTimeString()}</span>
      <span style="color:#333">·</span>
      <span id="footer-status" style="display:flex;align-items:center;gap:4px">
        <span style="width:5px;height:5px;border-radius:50%;background:#22c55e;display:inline-block;animation:footerPulse 2s infinite"></span>
        <span style="color:#22c55e44">LIVE</span>
      </span>
      <span style="color:#333">·</span>
      <span style="color:#333">TLS 1.3 · Zero-Trust</span>
      <span style="color:#333">·</span>
      <span style="color:#2d4a6e">© 2025 EYEbot AI</span>
    </div>
    <style>
      @keyframes footerPulse { 0%,100%{opacity:1} 50%{opacity:.4} }
    </style>
  `;

  document.body.appendChild(footer);

  // Update clock every second
  setInterval(() => {
    const el = document.getElementById('footer-time');
    if (el) el.textContent = new Date().toLocaleTimeString();
  }, 1000);

  // Add bottom padding to main content so it doesn't get hidden behind footer
  const contentArea = document.querySelector('.content-area') || document.querySelector('#contentArea');
  if (contentArea) contentArea.style.paddingBottom = '30px';
}

/* ─────────────────────────────────────────────
   APPLY BRANDING TO AI ORCHESTRATOR HEADER
───────────────────────────────────────────── */
function _applyAIHeaderBranding() {
  const aiHeader = document.querySelector('.ai-chat-header .ai-header-left img');
  if (aiHeader) {
    aiHeader.src = EYE_AI_BRAND.logoPath;
    aiHeader.style.cssText = 'width:28px;height:28px;object-fit:contain;border-radius:6px;';
  }
}

/* ─────────────────────────────────────────────
   EXPORT FOR MAIN.JS initApp()
───────────────────────────────────────────── */
window.initEyeAIBranding = initEyeAIBranding;
window.EYE_AI_BRAND      = EYE_AI_BRAND;

// Auto-init after page load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => setTimeout(initEyeAIBranding, 100));
} else {
  setTimeout(initEyeAIBranding, 100);
}

// Backward compatibility alias
window.EYE_AI_BRAND = EYE_AI_BRAND;
window.EYEBOT_AI_BRAND = EYE_AI_BRAND;
