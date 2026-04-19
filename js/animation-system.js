/**
 * animation-system.js — Skeleton factory + page transitions v1.0
 */
'use strict';
window.AnimationSystem = {
  skeletonRow: (cols = 3) => `<div style="display:flex;gap:12px;margin-bottom:10px;animation:pulse 1.5s infinite;">${Array(cols).fill(0).map(() => `<div style="flex:1;height:14px;background:#1e293b;border-radius:4px;"></div>`).join('')}</div>`,
  skeletonCard: () => `<div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:20px;animation:pulse 1.5s infinite;"><div style="height:16px;background:#1e293b;border-radius:4px;width:60%;margin-bottom:10px;"></div><div style="height:12px;background:#1e293b;border-radius:4px;width:40%;"></div></div>`,
  fadeIn: (el) => { if (el) { el.style.opacity = '0'; el.style.animation = 'fadeIn .35s ease forwards'; } },
};
