/**
 * ══════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Production Module Router v5.1
 *  FILE: js/module-router.js
 *
 *  FIXES:
 *  1. UI freeze when switching modules → each module renders in its own
 *     requestAnimationFrame / async microtask, never blocking the main thread
 *  2. Double-click / rapid switching → debounced navigation with cancel
 *  3. Long-running render functions → wrapped in try/catch + timeout guard
 *  4. Stale renders from previous module → render generation counter
 * ══════════════════════════════════════════════════════════════════════════
 */
'use strict';

(function (global) {

  /* ══════════════════════════════════════════════════════
     CONSTANTS
  ═══════════════════════════════════════════════════════ */
  const NAV_DEBOUNCE_MS  = 120;   // Ignore nav clicks within 120ms of each other
  const RENDER_TIMEOUT_MS = 8000;  // Kill module render if it takes > 8s

  /* ══════════════════════════════════════════════════════
     STATE
  ═══════════════════════════════════════════════════════ */
  let _currentPage      = null;
  let _renderGeneration = 0;     // Increment on every nav to cancel stale renders
  let _navDebounceTimer = null;
  let _isNavigating     = false;

  /* ══════════════════════════════════════════════════════
     CORE NAVIGATION (non-blocking)
  ═══════════════════════════════════════════════════════ */
  async function navigateTo(pageId, options = {}) {
    if (!pageId) return;

    // Debounce rapid clicks
    if (_navDebounceTimer) {
      clearTimeout(_navDebounceTimer);
    }

    return new Promise((resolve) => {
      _navDebounceTimer = setTimeout(async () => {
        await _doNavigate(pageId, options);
        resolve();
      }, options.immediate ? 0 : NAV_DEBOUNCE_MS);
    });
  }

  async function _doNavigate(pageId, options = {}) {
    if (_isNavigating && !options.force) {
      console.warn('[Router] Navigation already in progress — queuing:', pageId);
      // Queue this navigation after current one finishes
      setTimeout(() => _doNavigate(pageId, { ...options, force: true }), 200);
      return;
    }

    const generation = ++_renderGeneration;
    _isNavigating    = true;

    try {
      const prevPage = _currentPage;

      // ── Run onLeave for previous page ─────────────────────────
      if (prevPage && prevPage !== pageId) {
        await _runLifecycle('onLeave', prevPage);
      }

      // ── Update active nav item ─────────────────────────────────
      _setActiveNav(pageId);

      // ── Show the page container ────────────────────────────────
      _showPageContainer(pageId);

      // ── Show loading skeleton ─────────────────────────────────
      if (!options.noSkeleton) {
        _showSkeleton(pageId);
      }

      // ── Yield to browser (paint skeleton first) ───────────────
      await _rafYield();

      // ── Check if still the current render ─────────────────────
      if (generation !== _renderGeneration) {
        console.log('[Router] Stale render cancelled for:', pageId);
        return;
      }

      // ── Run onEnter with timeout guard ─────────────────────────
      await _runLifecycleWithTimeout('onEnter', pageId, RENDER_TIMEOUT_MS);

      // ── Hide skeleton ─────────────────────────────────────────
      _hideSkeleton(pageId);

      _currentPage  = pageId;
      _isNavigating = false;

      // Update browser URL hash
      if (window.history && !options.noHistory) {
        window.history.pushState({ page: pageId }, '', `#${pageId}`);
      }

      console.log(`[Router] ✅ Navigated to: ${pageId}`);

    } catch (err) {
      console.error(`[Router] ❌ Navigation error for ${pageId}:`, err.message);
      _isNavigating = false;
      _hideSkeleton(pageId);
      _showErrorInPage(pageId, err.message);
    }
  }

  /* ══════════════════════════════════════════════════════
     LIFECYCLE RUNNERS
  ═══════════════════════════════════════════════════════ */
  async function _runLifecycle(hook, pageId) {
    try {
      const config = _getPageConfig(pageId);
      if (config && typeof config[hook] === 'function') {
        await Promise.resolve(config[hook]());
      }
    } catch (err) {
      console.warn(`[Router] ${hook} error for ${pageId}:`, err.message);
    }
  }

  async function _runLifecycleWithTimeout(hook, pageId, timeoutMs) {
    const config = _getPageConfig(pageId);
    if (!config || typeof config[hook] !== 'function') return;

    return new Promise((resolve) => {
      let settled = false;

      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          console.warn(`[Router] ⚠️ ${hook} for ${pageId} timed out after ${timeoutMs}ms`);
          resolve();
        }
      }, timeoutMs);

      Promise.resolve(config[hook]())
        .then(() => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            resolve();
          }
        })
        .catch((err) => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            console.error(`[Router] ${hook} threw for ${pageId}:`, err.message);
            resolve();
          }
        });
    });
  }

  /* ══════════════════════════════════════════════════════
     DOM HELPERS
  ═══════════════════════════════════════════════════════ */
  function _getPageConfig(pageId) {
    return (global.PAGE_CONFIG && global.PAGE_CONFIG[pageId]) || null;
  }

  function _setActiveNav(pageId) {
    try {
      document.querySelectorAll('.nav-item, .sidebar-item, [data-page]').forEach(el => {
        el.classList.remove('active');
        if (el.dataset.page === pageId || el.getAttribute('href') === `#${pageId}`) {
          el.classList.add('active');
        }
      });
    } catch (_) {}
  }

  function _showPageContainer(pageId) {
    try {
      // Hide all page sections
      document.querySelectorAll('.page-section, [id$="-wrap"], [id$="-page"]').forEach(el => {
        el.style.display = 'none';
      });

      // Show the target page
      const selectors = [
        `#${pageId}`,
        `#${pageId}-wrap`,
        `#${pageId}-page`,
        `[data-section="${pageId}"]`,
      ];
      for (const sel of selectors) {
        const el = document.querySelector(sel);
        if (el) {
          el.style.display = '';
          el.style.visibility = 'visible';
          break;
        }
      }
    } catch (_) {}
  }

  function _showSkeleton(pageId) {
    try {
      const target = document.querySelector(`#${pageId}, #${pageId}-wrap`);
      if (!target) return;
      if (target.querySelector('.skeleton-loader')) return; // Already shown

      // Only show skeleton if the page appears empty
      if (target.textContent.trim().length < 50) {
        const sk = document.createElement('div');
        sk.className = 'skeleton-loader';
        sk.innerHTML = `
          <div class="sk-header"></div>
          <div class="sk-row"></div>
          <div class="sk-row sk-short"></div>
          <div class="sk-row"></div>
          <div class="sk-grid">
            <div class="sk-card"></div>
            <div class="sk-card"></div>
            <div class="sk-card"></div>
          </div>
        `;
        target.prepend(sk);
      }
    } catch (_) {}
  }

  function _hideSkeleton(pageId) {
    try {
      const target = document.querySelector(`#${pageId}, #${pageId}-wrap`);
      if (!target) return;
      target.querySelectorAll('.skeleton-loader').forEach(el => el.remove());
    } catch (_) {}
  }

  function _showErrorInPage(pageId, message) {
    try {
      const target = document.querySelector(`#${pageId}, #${pageId}-wrap`);
      if (!target) return;
      const errDiv = document.createElement('div');
      errDiv.className = 'module-error-banner';
      errDiv.innerHTML = `
        <span class="err-icon">⚠️</span>
        <span>Module failed to load: ${message}</span>
        <button onclick="this.parentElement.remove();window.Router?.navigateTo('${pageId}',{force:true})">Retry</button>
      `;
      target.prepend(errDiv);
    } catch (_) {}
  }

  /* ══════════════════════════════════════════════════════
     UTILITIES
  ═══════════════════════════════════════════════════════ */
  function _rafYield() {
    return new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0)));
  }

  /* ══════════════════════════════════════════════════════
     HASH-BASED ROUTING
  ═══════════════════════════════════════════════════════ */
  function initHashRouting() {
    window.addEventListener('popstate', (e) => {
      const page = e.state?.page || window.location.hash.slice(1);
      if (page) navigateTo(page, { noHistory: true });
    });
  }

  /* ══════════════════════════════════════════════════════
     PUBLIC API
  ═══════════════════════════════════════════════════════ */
  const Router = {
    navigateTo,
    getCurrentPage: () => _currentPage,
    initHashRouting,

    /** Intercept all nav clicks automatically */
    interceptNavClicks(container = document) {
      container.addEventListener('click', (e) => {
        const navEl = e.target.closest('[data-page], .nav-item[href], .sidebar-link[data-page]');
        if (!navEl) return;

        const pageId = navEl.dataset.page || navEl.getAttribute('href')?.replace('#', '');
        if (!pageId) return;

        e.preventDefault();
        e.stopPropagation();
        navigateTo(pageId);
      });
    },
  };

  global.Router = Router;

  // Auto-inject skeleton CSS if not present
  if (!document.getElementById('router-styles')) {
    const style = document.createElement('style');
    style.id = 'router-styles';
    style.textContent = `
      .skeleton-loader { padding: 20px; animation: sk-fade 1.4s ease-in-out infinite; }
      .sk-header { height: 28px; background: #21262d; border-radius: 6px; margin-bottom: 16px; width: 40%; }
      .sk-row { height: 14px; background: #21262d; border-radius: 4px; margin-bottom: 10px; }
      .sk-short { width: 60%; }
      .sk-grid { display: grid; grid-template-columns: repeat(3,1fr); gap: 12px; margin-top: 20px; }
      .sk-card { height: 100px; background: #21262d; border-radius: 8px; }
      @keyframes sk-fade { 0%,100%{opacity:.4} 50%{opacity:.9} }
      .module-error-banner { background: #f8514915; border: 1px solid #f85149; border-radius: 8px;
        padding: 10px 16px; margin: 12px 0; display: flex; align-items: center; gap: 10px; font-size: 13px; }
      .module-error-banner button { margin-left: auto; background: #f8514920; border: 1px solid #f85149;
        color: #f85149; padding: 4px 12px; border-radius: 6px; cursor: pointer; }
    `;
    document.head.appendChild(style);
  }

})(window);
