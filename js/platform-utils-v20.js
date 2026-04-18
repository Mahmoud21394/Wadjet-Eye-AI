/* ═══════════════════════════════════════════════════════════════════
   Wadjet-Eye AI — Toast Notification System v20.0
   + Global Platform Utilities
   ═══════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  /* ══════════════════════════════════════════════
     TOAST SYSTEM
  ══════════════════════════════════════════════ */
  const TOAST_ICONS = {
    success: 'fa-check-circle',
    error:   'fa-times-circle',
    warning: 'fa-exclamation-triangle',
    info:    'fa-info-circle'
  };

  function _ensureToastContainer() {
    let wrap = document.getElementById('p20-toast-wrap');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'p20-toast-wrap';
      document.body.appendChild(wrap);
    }
    return wrap;
  }

  function _p20ShowToast(message, type = 'info', duration = 4000) {
    const wrap = _ensureToastContainer();
    const icon = TOAST_ICONS[type] || TOAST_ICONS.info;

    const toast = document.createElement('div');
    toast.className = `p20-toast p20-toast-${type}`;
    toast.innerHTML = `
      <div class="p20-toast-icon"><i class="fas ${icon}"></i></div>
      <div class="p20-toast-msg">${String(message).replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
      <button class="p20-toast-close" onclick="this.closest('.p20-toast').dispatchEvent(new Event('dismiss'))">
        <i class="fas fa-times"></i>
      </button>
    `;

    toast.addEventListener('dismiss', () => _dismissToast(toast));
    toast.addEventListener('click', () => _dismissToast(toast));

    wrap.appendChild(toast);

    // Auto-dismiss
    if (duration > 0) {
      setTimeout(() => _dismissToast(toast), duration);
    }

    // Limit queue to 5
    const toasts = wrap.querySelectorAll('.p20-toast');
    if (toasts.length > 5) {
      _dismissToast(toasts[0]);
    }
  }

  function _dismissToast(toast) {
    if (!toast || toast.dataset.dismissing) return;
    toast.dataset.dismissing = 'true';
    toast.classList.add('leaving');
    setTimeout(() => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 300);
  }

  // Install globally — override/complement existing showToast
  const _origShowToast = window.showToast;
  window.showToast = function (message, type = 'info', duration = 4000) {
    _p20ShowToast(message, type, duration);
    // Also call original if it does something else (analytics, etc.)
    if (typeof _origShowToast === 'function') {
      try { _origShowToast(message, type, duration); } catch {}
    }
  };

  window.p20Toast = _p20ShowToast;

  /* ══════════════════════════════════════════════
     MOBILE SIDEBAR TOGGLE
  ══════════════════════════════════════════════ */
  function _initMobileSidebar() {
    const toggleBtn = document.getElementById('sidebarToggle');
    const sidebar   = document.getElementById('sidebar');
    const wrapper   = document.getElementById('mainWrapper');

    if (!toggleBtn || !sidebar) return;

    // Create overlay
    let overlay = document.getElementById('sidebarOverlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'sidebarOverlay';
      overlay.style.cssText = `
        position: fixed; inset: 0; background: rgba(0,0,0,0.6);
        z-index: 999; display: none; backdrop-filter: blur(2px);
      `;
      document.body.appendChild(overlay);
    }

    toggleBtn.addEventListener('click', () => {
      const isOpen = sidebar.classList.contains('open');
      sidebar.classList.toggle('open', !isOpen);
      overlay.style.display = isOpen ? 'none' : 'block';
    });

    overlay.addEventListener('click', () => {
      sidebar.classList.remove('open');
      overlay.style.display = 'none';
    });
  }

  /* ══════════════════════════════════════════════
     KEYBOARD SHORTCUTS
  ══════════════════════════════════════════════ */
  function _initKeyboardShortcuts() {
    document.addEventListener('keydown', function (e) {
      // Ctrl+K → focus search
      if (e.ctrlKey && e.key === 'k') {
        e.preventDefault();
        const search = document.getElementById('globalSearch');
        if (search) search.focus();
      }
      // Escape → close dropdowns/modals
      if (e.key === 'Escape') {
        document.querySelectorAll('.notif-dropdown.open, .ai-provider-menu.open').forEach(el => {
          el.classList.remove('open');
        });
        document.querySelectorAll('.modal-overlay.active').forEach(el => {
          el.classList.remove('active');
        });
      }
    });
  }

  /* ══════════════════════════════════════════════
     STAGGERED CARD ANIMATIONS ON PAGE ENTER
  ══════════════════════════════════════════════ */
  function _initStaggeredAnimations() {
    // Use MutationObserver to detect when new pages become active
    const observer = new MutationObserver((mutations) => {
      mutations.forEach(m => {
        m.addedNodes.forEach(node => {
          if (node.nodeType === 1 && node.classList && node.classList.contains('active')) {
            _staggerChildren(node);
          }
        });
        if (m.type === 'attributes' && m.target.classList.contains('active')) {
          _staggerChildren(m.target);
        }
      });
    });

    const contentArea = document.getElementById('contentArea');
    if (contentArea) {
      observer.observe(contentArea, { childList: true, subtree: true, attributes: true, attributeFilter: ['class'] });
    }
  }

  function _staggerChildren(parent) {
    const items = parent.querySelectorAll('.metric-card, .threat-card, .ioc-card, .actor-card');
    items.forEach((item, i) => {
      item.style.animationDelay = (i * 0.06) + 's';
      item.style.animation = 'none';
      void item.offsetWidth;
      item.style.animation = `p20-fadeInUp 0.4s ${i * 0.06}s ease both`;
    });
  }

  /* ══════════════════════════════════════════════
     PROGRESS BARS — ANIMATED ON APPEAR
  ══════════════════════════════════════════════ */
  function _initProgressBars() {
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          const bar = e.target;
          const target = bar.dataset.progress || bar.style.width;
          bar.style.width = '0';
          setTimeout(() => {
            bar.style.transition = 'width 0.8s cubic-bezier(0.4,0,0.2,1)';
            bar.style.width = target;
          }, 100);
          io.unobserve(bar);
        }
      });
    }, { threshold: 0.1 });

    document.querySelectorAll('[class*="progress-fill"], [class*="bar-fill"]').forEach(bar => {
      io.observe(bar);
    });
  }

  /* ══════════════════════════════════════════════
     COPY-TO-CLIPBOARD UTILITY
  ══════════════════════════════════════════════ */
  window.p20Copy = async function (text, label = 'Value') {
    try {
      await navigator.clipboard.writeText(text);
      window.showToast(`📋 ${label} copied to clipboard`, 'success', 2000);
    } catch {
      window.showToast('Copy failed — manual copy required', 'warning');
    }
  };

  /* ══════════════════════════════════════════════
     CONFIRMATION DIALOG
  ══════════════════════════════════════════════ */
  window.p20Confirm = function (message, onConfirm, onCancel) {
    const modal = document.createElement('div');
    modal.style.cssText = `
      position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:99990;
      display:flex;align-items:center;justify-content:center;
      backdrop-filter:blur(4px);animation:p20-fadeIn 0.2s ease;
    `;
    modal.innerHTML = `
      <div style="background:#0a1628;border:1px solid rgba(0,212,255,0.2);border-radius:16px;padding:28px;max-width:380px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,0.5);animation:p20-modalIn 0.3s ease both;">
        <div style="font-size:20px;text-align:center;margin-bottom:14px;">⚠️</div>
        <div style="font-size:14px;color:#e2e8f0;text-align:center;line-height:1.6;margin-bottom:24px;">${String(message).replace(/</g,'&lt;')}</div>
        <div style="display:flex;gap:10px;justify-content:center;">
          <button onclick="this.closest('[style]').querySelector('[data-action=cancel]').click()"
            style="padding:9px 22px;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.12);border-radius:8px;color:#94a3b8;cursor:pointer;font-size:13px;font-family:'Inter',sans-serif;">
            Cancel
          </button>
          <button data-action="confirm"
            style="padding:9px 22px;background:linear-gradient(135deg,#ef4444,#dc2626);border:none;border-radius:8px;color:#fff;cursor:pointer;font-size:13px;font-weight:700;font-family:'Inter',sans-serif;box-shadow:0 4px 12px rgba(239,68,68,0.3);">
            Confirm
          </button>
        </div>
        <button data-action="cancel" style="display:none;"></button>
      </div>
    `;

    modal.querySelector('[data-action="confirm"]').addEventListener('click', () => {
      document.body.removeChild(modal);
      if (typeof onConfirm === 'function') onConfirm();
    });

    modal.querySelector('[data-action="cancel"]').addEventListener('click', () => {
      document.body.removeChild(modal);
      if (typeof onCancel === 'function') onCancel();
    });

    document.body.appendChild(modal);
  };

  /* ══════════════════════════════════════════════
     INIT
  ══════════════════════════════════════════════ */
  function _init() {
    _ensureToastContainer();
    _initMobileSidebar();
    _initKeyboardShortcuts();
    _initStaggeredAnimations();

    // Delayed init for elements that load late
    setTimeout(_initProgressBars, 1000);

    // Global error handler (non-intrusive)
    window.addEventListener('unhandledrejection', function (e) {
      if (e.reason && e.reason.message && !e.reason.message.includes('AbortError')) {
        console.error('[Platform] Unhandled promise rejection:', e.reason);
      }
    });

  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _init);
  } else {
    _init();
  }

})();
