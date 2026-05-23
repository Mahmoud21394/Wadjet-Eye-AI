#!/usr/bin/env python3
"""Build script for css/threat-modules-v2.css"""
import os

CSS = r"""/* ══════════════════════════════════════════════════════════════════════════
 * Wadjet-Eye AI v25.0 — Threat Intelligence Modules v2 Shared Stylesheet
 * FILE: css/threat-modules-v2.css
 *
 * Covers:
 *   1. Threat Intelligence Graph v2  (threat-graph-v2.js)  — all .tgv2-* classes
 *   2. Global Threat Landscape       (global-threat-landscape.js) — all .gtl-* classes
 * ══════════════════════════════════════════════════════════════════════════ */

/* ─────────────────────────────────────────────────────────────
   CSS CUSTOM PROPERTIES
───────────────────────────────────────────────────────────────*/
:root {
  --tm-bg0:     #070b14;
  --tm-bg1:     #0d1526;
  --tm-bg2:     #111d35;
  --tm-bg3:     #162040;
  --tm-border:  #1e3a5f;
  --tm-border2: #243b5f;
  --tm-accent:  #00d4ff;
  --tm-red:     #ef4444;
  --tm-orange:  #f97316;
  --tm-amber:   #f59e0b;
  --tm-green:   #22c55e;
  --tm-blue:    #3b82f6;
  --tm-purple:  #a855f7;
  --tm-pink:    #ec4899;
  --tm-text:    #e2e8f0;
  --tm-muted:   #64748b;
  --tm-crit:    #ff2d55;
  --tm-high:    #ff6b35;
  --tm-med:     #ffd60a;
  --tm-low:     #34d399;
  --tm-radius:  8px;
  --tm-radius-sm: 4px;
  --tm-transition: 0.18s ease;
}

/* ═══════════════════════════════════════════════════════════════════════════
   PART 1 — THREAT INTELLIGENCE GRAPH v2 (.tgv2-*)
═══════════════════════════════════════════════════════════════════════════ */

/* Root container */
.tgv2-root {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 600px;
  background: var(--tm-bg0);
  color: var(--tm-text);
  font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
  font-size: 13px;
  position: relative;
  overflow: hidden;
}

/* Header */
.tgv2-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 16px;
  background: var(--tm-bg1);
  border-bottom: 1px solid var(--tm-border);
  flex-shrink: 0;
  gap: 12px;
  flex-wrap: wrap;
}

.tgv2-header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.tgv2-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--tm-text);
  display: flex;
  align-items: center;
  gap: 8px;
}

.tgv2-version {
  font-size: 10px;
  color: var(--tm-accent);
  background: rgba(0,212,255,.1);
  border: 1px solid rgba(0,212,255,.3);
  border-radius: 20px;
  padding: 1px 7px;
}

.tgv2-live-dot {
  width: 7px; height: 7px;
  border-radius: 50%;
  background: var(--tm-green);
  box-shadow: 0 0 6px var(--tm-green);
  animation: tmPulse 1.4s infinite;
}

.tgv2-header-controls {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

/* Node count badge */
.tgv2-node-count {
  font-size: 11px;
  color: var(--tm-muted);
  background: var(--tm-bg2);
  border: 1px solid var(--tm-border);
  border-radius: 20px;
  padding: 3px 10px;
}

/* ── Graph area ── */
.tgv2-graph-area {
  flex: 1;
  position: relative;
  overflow: hidden;
  background: radial-gradient(ellipse at 50% 40%, #0d1e3d 0%, var(--tm-bg0) 70%);
}

.tgv2-canvas {
  position: absolute;
  top: 0; left: 0;
  display: block;
  cursor: grab;
}
.tgv2-canvas:active { cursor: grabbing; }

/* Zoom controls */
.tgv2-zoom-controls {
  position: absolute;
  bottom: 16px;
  right: 16px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  z-index: 10;
}

/* ── Tooltip ── */
.tgv2-tooltip {
  position: absolute;
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border2);
  border-radius: var(--tm-radius);
  padding: 12px 14px;
  min-width: 200px;
  max-width: 300px;
  pointer-events: none;
  z-index: 100;
  box-shadow: 0 8px 32px rgba(0,0,0,.5);
  animation: tmFadeIn 0.15s ease;
}

.tgv2-tooltip-title {
  font-size: 13px;
  font-weight: 700;
  color: var(--tm-text);
  margin-bottom: 4px;
}

.tgv2-tooltip-type {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 8px;
}

.tgv2-tooltip-row {
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  margin-bottom: 3px;
  gap: 12px;
}

.tgv2-tooltip-row span:first-child { color: var(--tm-muted); }
.tgv2-tooltip-row span:last-child  { color: var(--tm-text); font-weight: 600; }

/* ── Right panel (narrator + side panels) ── */
.tgv2-right-panel {
  position: absolute;
  right: 0; top: 0; bottom: 0;
  width: 320px;
  background: var(--tm-bg1);
  border-left: 1px solid var(--tm-border);
  display: flex;
  flex-direction: column;
  z-index: 20;
  transform: translateX(0);
  transition: transform var(--tm-transition);
  overflow: hidden;
}

.tgv2-right-panel.tgv2-panel-hidden {
  transform: translateX(320px);
}

.tgv2-panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 14px;
  border-bottom: 1px solid var(--tm-border);
  flex-shrink: 0;
}

.tgv2-panel-title {
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--tm-accent);
  display: flex;
  align-items: center;
  gap: 6px;
}

.tgv2-panel-close {
  background: none;
  border: none;
  color: var(--tm-muted);
  cursor: pointer;
  padding: 4px;
  border-radius: 4px;
  transition: color var(--tm-transition);
}
.tgv2-panel-close:hover { color: var(--tm-text); }

.tgv2-panel-body {
  flex: 1;
  overflow-y: auto;
  padding: 14px;
  scrollbar-width: thin;
  scrollbar-color: var(--tm-border) transparent;
}

/* ── Narrator panel ── */
.tgv2-narrator-bubble {
  background: var(--tm-bg2);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
  padding: 12px;
  margin-bottom: 10px;
  font-size: 12px;
  line-height: 1.6;
  color: var(--tm-text);
  animation: tmFadeIn 0.3s ease;
  position: relative;
}

.tgv2-narrator-bubble::before {
  content: '▶';
  font-size: 8px;
  color: var(--tm-accent);
  margin-right: 6px;
}

.tgv2-narrator-action {
  font-size: 10px;
  color: var(--tm-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 6px;
}

.tgv2-narrator-typing::after {
  content: '▋';
  animation: tmBlink 0.7s infinite;
}

/* ── Node detail panel ── */
.tgv2-node-detail {
  background: var(--tm-bg2);
  border-radius: var(--tm-radius);
  padding: 14px;
  margin-bottom: 12px;
  border: 1px solid var(--tm-border);
}

.tgv2-node-detail-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
}

.tgv2-node-icon-large {
  width: 40px; height: 40px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
  flex-shrink: 0;
}

.tgv2-node-name {
  font-size: 15px;
  font-weight: 700;
  color: var(--tm-text);
}

.tgv2-node-meta {
  font-size: 11px;
  color: var(--tm-muted);
  margin-top: 2px;
}

.tgv2-detail-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 5px 0;
  border-bottom: 1px solid var(--tm-border);
  font-size: 12px;
}

.tgv2-detail-row:last-child { border-bottom: none; }
.tgv2-detail-label { color: var(--tm-muted); }
.tgv2-detail-value { color: var(--tm-text); font-weight: 600; }

/* ── Attack path panel ── */
.tgv2-path-panel {
  animation: tmSlideIn 0.25s ease;
}

.tgv2-path-step {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  margin-bottom: 14px;
}

.tgv2-path-step-num {
  width: 22px; height: 22px;
  border-radius: 50%;
  background: var(--tm-accent);
  color: var(--tm-bg0);
  font-size: 10px;
  font-weight: 800;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  margin-top: 2px;
}

.tgv2-path-step-content { flex: 1; }

.tgv2-path-step-node {
  font-weight: 700;
  font-size: 13px;
  color: var(--tm-text);
}

.tgv2-path-step-ttp {
  font-size: 10px;
  color: var(--tm-blue);
  background: rgba(59,130,246,.1);
  border: 1px solid rgba(59,130,246,.3);
  border-radius: 4px;
  padding: 2px 6px;
  display: inline-block;
  margin-top: 3px;
}

.tgv2-path-step-desc {
  font-size: 11px;
  color: var(--tm-muted);
  margin-top: 4px;
  line-height: 1.5;
}

.tgv2-path-connector {
  width: 1px;
  height: 12px;
  background: var(--tm-accent);
  margin: 0 0 0 11px;
  opacity: 0.4;
}

/* ETA bar */
.tgv2-path-eta {
  background: rgba(239,68,68,.1);
  border: 1px solid rgba(239,68,68,.3);
  border-radius: var(--tm-radius-sm);
  padding: 8px 10px;
  margin-bottom: 12px;
  font-size: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}

/* ── Blast radius panel ── */
.tgv2-blast-panel {
  animation: tmFadeIn 0.25s ease;
}

.tgv2-blast-ring {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 10px;
  border-radius: var(--tm-radius-sm);
  margin-bottom: 8px;
  border: 1px solid transparent;
}

.tgv2-blast-ring.ring1 { background:rgba(255,45,85,.08);  border-color:rgba(255,45,85,.25);  }
.tgv2-blast-ring.ring2 { background:rgba(249,115,22,.08); border-color:rgba(249,115,22,.25); }
.tgv2-blast-ring.ring3 { background:rgba(245,158,11,.08); border-color:rgba(245,158,11,.25); }

.tgv2-blast-ring-indicator {
  width: 12px; height: 12px;
  border-radius: 50%;
  border: 2px solid;
  flex-shrink: 0;
  margin-top: 2px;
}

.ring1 .tgv2-blast-ring-indicator { border-color: var(--tm-crit); box-shadow: 0 0 6px var(--tm-crit); }
.ring2 .tgv2-blast-ring-indicator { border-color: var(--tm-orange); box-shadow: 0 0 6px var(--tm-orange); }
.ring3 .tgv2-blast-ring-indicator { border-color: var(--tm-amber); box-shadow: 0 0 6px var(--tm-amber); }

.tgv2-blast-ring-title {
  font-size: 12px;
  font-weight: 700;
  margin-bottom: 3px;
}

.tgv2-blast-ring-desc {
  font-size: 11px;
  color: var(--tm-muted);
  line-height: 1.5;
}

.tgv2-blast-ring-count {
  font-size: 18px;
  font-weight: 800;
  margin-right: 8px;
}

/* ── Temporal strip ── */
.tgv2-temporal-strip {
  background: var(--tm-bg1);
  border-top: 1px solid var(--tm-border);
  padding: 8px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
  flex-wrap: wrap;
}

.tgv2-temporal-strip.tgv2-hidden { display: none; }

.tgv2-temporal-date {
  font-family: monospace;
  font-size: 11px;
  color: var(--tm-accent);
  background: rgba(0,212,255,.1);
  border: 1px solid rgba(0,212,255,.2);
  border-radius: 4px;
  padding: 2px 8px;
  min-width: 90px;
  text-align: center;
}

.tgv2-temporal-slider {
  flex: 1;
  min-width: 120px;
  accent-color: var(--tm-accent);
  cursor: pointer;
  height: 4px;
}

.tgv2-temporal-controls {
  display: flex;
  align-items: center;
  gap: 6px;
}

.tgv2-event-markers {
  display: flex;
  align-items: center;
  gap: 4px;
  overflow-x: auto;
}

.tgv2-event-marker {
  font-size: 9px;
  padding: 2px 6px;
  border-radius: 3px;
  cursor: pointer;
  white-space: nowrap;
  background: rgba(255,255,255,.04);
  border: 1px solid var(--tm-border);
  color: var(--tm-muted);
  transition: all var(--tm-transition);
}

.tgv2-event-marker:hover {
  background: rgba(0,212,255,.1);
  border-color: var(--tm-accent);
  color: var(--tm-accent);
}

.tgv2-delta-badge {
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 20px;
  border: 1px solid;
}

.tgv2-delta-new    { color: var(--tm-green);  background: rgba(34,197,94,.1);  border-color: rgba(34,197,94,.3); }
.tgv2-delta-removed{ color: var(--tm-crit);   background: rgba(255,45,85,.1);  border-color: rgba(255,45,85,.3); }
.tgv2-delta-changed{ color: var(--tm-amber);  background: rgba(245,158,11,.1); border-color: rgba(245,158,11,.3); }

/* ── Lens filter panel ── */
.tgv2-lens-panel {
  position: absolute;
  top: 60px; left: 0;
  width: 380px;
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-left: none;
  border-radius: 0 var(--tm-radius) var(--tm-radius) 0;
  padding: 16px;
  z-index: 50;
  box-shadow: 4px 0 24px rgba(0,0,0,.4);
  animation: tmSlideIn 0.2s ease;
  max-height: 80vh;
  overflow-y: auto;
}

.tgv2-lens-panel.tgv2-hidden { display: none; }

.tgv2-lens-section-title {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--tm-muted);
  margin: 10px 0 6px 0;
}

.tgv2-lens-section-title:first-child { margin-top: 0; }

.tgv2-lens-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.tgv2-lens-tag {
  font-size: 11px;
  padding: 3px 10px;
  border-radius: 20px;
  border: 1px solid var(--tm-border);
  cursor: pointer;
  background: var(--tm-bg2);
  color: var(--tm-muted);
  transition: all var(--tm-transition);
  user-select: none;
}

.tgv2-lens-tag:hover, .tgv2-lens-tag.tgv2-tag-active {
  background: rgba(0,212,255,.1);
  border-color: var(--tm-accent);
  color: var(--tm-accent);
}

.tgv2-lens-tag.tgv2-tag-active {
  font-weight: 600;
}

.tgv2-lens-pills {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  padding: 8px 16px;
  background: var(--tm-bg1);
  border-bottom: 1px solid var(--tm-border);
  flex-shrink: 0;
  min-height: 38px;
}

.tgv2-lens-pill {
  font-size: 11px;
  padding: 3px 8px 3px 10px;
  border-radius: 20px;
  background: rgba(0,212,255,.1);
  border: 1px solid rgba(0,212,255,.3);
  color: var(--tm-accent);
  display: flex;
  align-items: center;
  gap: 5px;
  animation: tmPopIn 0.2s ease;
}

.tgv2-pill-close {
  cursor: pointer;
  opacity: 0.7;
  font-size: 10px;
  line-height: 1;
  padding: 1px;
}
.tgv2-pill-close:hover { opacity: 1; }

.tgv2-lens-composition {
  display: flex;
  gap: 8px;
  margin-top: 8px;
}

.tgv2-comp-btn {
  font-size: 11px;
  padding: 4px 12px;
  border-radius: 20px;
  border: 1px solid var(--tm-border);
  cursor: pointer;
  background: var(--tm-bg2);
  color: var(--tm-muted);
  transition: all var(--tm-transition);
}

.tgv2-comp-btn.active, .tgv2-comp-btn:hover {
  background: rgba(0,212,255,.1);
  border-color: var(--tm-accent);
  color: var(--tm-accent);
}

/* ── Ego breadcrumb ── */
.tgv2-ego-breadcrumb {
  position: absolute;
  top: 10px; left: 10px;
  display: flex;
  align-items: center;
  gap: 6px;
  z-index: 15;
  animation: tmFadeIn 0.2s ease;
}

.tgv2-ego-crumb {
  font-size: 11px;
  padding: 4px 10px;
  border-radius: 20px;
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  color: var(--tm-muted);
  cursor: pointer;
  transition: all var(--tm-transition);
}

.tgv2-ego-crumb.tgv2-crumb-active {
  background: rgba(0,212,255,.1);
  border-color: var(--tm-accent);
  color: var(--tm-accent);
}

.tgv2-ego-crumb:hover { color: var(--tm-accent); }

/* ── Context menu ── */
.tgv2-ctx-menu {
  position: fixed;
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
  padding: 4px 0;
  z-index: 200;
  min-width: 190px;
  box-shadow: 0 8px 24px rgba(0,0,0,.5);
  animation: tmPopIn 0.15s ease;
}

.tgv2-ctx-item {
  padding: 8px 14px;
  font-size: 12px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--tm-text);
  transition: background var(--tm-transition);
}

.tgv2-ctx-item:hover { background: rgba(255,255,255,.05); }

.tgv2-ctx-item i { width: 14px; text-align: center; color: var(--tm-muted); }

.tgv2-ctx-sep {
  height: 1px;
  background: var(--tm-border);
  margin: 3px 0;
}

/* Shared buttons */
.tgv2-btn {
  font-size: 12px;
  padding: 6px 12px;
  border-radius: var(--tm-radius-sm);
  border: 1px solid var(--tm-border);
  cursor: pointer;
  background: var(--tm-bg2);
  color: var(--tm-text);
  display: flex;
  align-items: center;
  gap: 6px;
  transition: all var(--tm-transition);
  white-space: nowrap;
}

.tgv2-btn:hover {
  background: var(--tm-bg3);
  border-color: var(--tm-border2);
}

.tgv2-btn.tgv2-btn-primary {
  background: rgba(0,212,255,.1);
  border-color: rgba(0,212,255,.4);
  color: var(--tm-accent);
}

.tgv2-btn.tgv2-btn-primary:hover {
  background: rgba(0,212,255,.2);
}

.tgv2-btn.tgv2-btn-active {
  background: rgba(0,212,255,.15);
  border-color: var(--tm-accent);
  color: var(--tm-accent);
}

.tgv2-btn.tgv2-btn-danger { color: var(--tm-crit); border-color: rgba(255,45,85,.3); }
.tgv2-btn.tgv2-btn-danger:hover { background: rgba(255,45,85,.1); }

/* Export buttons */
.tgv2-export-row {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  margin-top: 12px;
}

/* Shared input */
.tgv2-input {
  background: var(--tm-bg2);
  border: 1px solid var(--tm-border);
  color: var(--tm-text);
  border-radius: var(--tm-radius-sm);
  padding: 6px 10px;
  font-size: 12px;
  outline: none;
  transition: border-color var(--tm-transition);
}
.tgv2-input:focus { border-color: var(--tm-accent); }

/* Shift-click hint */
.tgv2-hint {
  position: absolute;
  bottom: 50px;
  left: 50%;
  transform: translateX(-50%);
  font-size: 11px;
  color: var(--tm-muted);
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-radius: 20px;
  padding: 4px 14px;
  pointer-events: none;
  animation: tmFadeIn 0.3s ease;
  z-index: 5;
}

/* Loading spinner */
.tgv2-loading {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(7,11,20,.8);
  z-index: 30;
}

.tgv2-spinner {
  width: 32px; height: 32px;
  border: 3px solid var(--tm-border);
  border-top-color: var(--tm-accent);
  border-radius: 50%;
  animation: tmSpin 0.8s linear infinite;
}

/* ═══════════════════════════════════════════════════════════════════════════
   PART 2 — GLOBAL THREAT LANDSCAPE (.gtl-*)
═══════════════════════════════════════════════════════════════════════════ */

/* Root */
.gtl-root {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 600px;
  background: var(--tm-bg0);
  color: var(--tm-text);
  font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
  font-size: 13px;
  overflow: hidden;
}

/* ── Header ── */
.gtl-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 18px;
  background: var(--tm-bg1);
  border-bottom: 1px solid var(--tm-border);
  flex-shrink: 0;
  gap: 12px;
  flex-wrap: wrap;
}

.gtl-header-left { display: flex; align-items: center; gap: 14px; }
.gtl-header-right { display: flex; align-items: center; gap: 10px; }

.gtl-logo {
  display: flex;
  align-items: center;
  gap: 8px;
}

.gtl-logo-text {
  font-size: 15px;
  font-weight: 700;
  color: var(--tm-text);
  letter-spacing: -0.3px;
}

.gtl-version-chip {
  font-size: 9px;
  color: var(--tm-accent);
  background: rgba(0,212,255,.08);
  border: 1px solid rgba(0,212,255,.25);
  border-radius: 20px;
  padding: 1px 7px;
}

.gtl-live-indicator {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  color: var(--tm-green);
  background: rgba(34,197,94,.08);
  border: 1px solid rgba(34,197,94,.2);
  border-radius: 20px;
  padding: 3px 10px;
}

.gtl-threat-level-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
}

.gtl-threat-gauge {
  width: 80px;
  height: 6px;
  background: var(--tm-bg3);
  border-radius: 3px;
  overflow: hidden;
}

.gtl-threat-bar {
  height: 100%;
  border-radius: 3px;
  background: linear-gradient(90deg, var(--tm-orange), var(--tm-crit));
  transition: width 0.5s ease;
}

/* ── Tab bar ── */
.gtl-tabs {
  display: flex;
  align-items: center;
  background: var(--tm-bg1);
  border-bottom: 1px solid var(--tm-border);
  flex-shrink: 0;
  overflow-x: auto;
  scrollbar-width: none;
}
.gtl-tabs::-webkit-scrollbar { display: none; }

.gtl-tab {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 10px 16px;
  font-size: 12px;
  font-weight: 500;
  color: var(--tm-muted);
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  white-space: nowrap;
  transition: all var(--tm-transition);
}

.gtl-tab:hover { color: var(--tm-text); }

.gtl-tab-active {
  color: var(--tm-accent);
  border-bottom-color: var(--tm-accent);
  background: rgba(0,212,255,.04);
}

/* ── Content ── */
.gtl-content {
  flex: 1;
  overflow: hidden;
  position: relative;
}

.gtl-panel {
  height: 100%;
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: var(--tm-border) transparent;
}

.gtl-panel-inner {
  padding: 18px;
  min-height: 100%;
}

.gtl-panel-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--tm-text);
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.gtl-panel-title i { color: var(--tm-accent); }

/* ── World map layout ── */
.gtl-worldmap-grid {
  display: grid;
  grid-template-columns: 1fr 280px;
  gap: 16px;
  height: calc(100vh - 160px);
  min-height: 500px;
}

.gtl-map-main-col {
  display: flex;
  flex-direction: column;
  gap: 10px;
  min-height: 0;
}

.gtl-map-sigint-col {
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
  padding: 14px;
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: var(--tm-border) transparent;
}

/* Map KPI row */
.gtl-map-kpi-row {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.gtl-map-kpi {
  flex: 1;
  min-width: 120px;
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
  padding: 10px 14px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 3px;
}

.gtl-map-kpi-val {
  font-size: 22px;
  font-weight: 800;
  line-height: 1;
}

.gtl-map-kpi span:last-child {
  font-size: 10px;
  color: var(--tm-muted);
  text-align: center;
}

/* SVG Map */
.gtl-map-wrap {
  position: relative;
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
  overflow: hidden;
}

.gtl-world-svg {
  width: 100%;
  height: auto;
  display: block;
}

.gtl-map-country {
  transition: stroke-width 0.2s, opacity 0.2s;
}

.gtl-map-country:hover {
  opacity: 0.85;
  stroke-width: 2 !important;
}

/* Map legend */
.gtl-map-legend {
  position: absolute;
  bottom: 10px;
  left: 10px;
  display: flex;
  flex-direction: column;
  gap: 3px;
  background: rgba(7,11,20,.85);
  padding: 8px 10px;
  border-radius: var(--tm-radius-sm);
  border: 1px solid var(--tm-border);
}

.gtl-legend-item {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 10px;
  color: var(--tm-muted);
}

.gtl-legend-swatch {
  width: 14px; height: 8px;
  border-radius: 2px;
  flex-shrink: 0;
}

/* Spotlight panel */
.gtl-map-spotlight {
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
  min-height: 60px;
}

/* ── Actor registry ── */
.gtl-registry-toolbar {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}

.gtl-search-wrap {
  position: relative;
  flex: 1;
  min-width: 200px;
}

.gtl-search-wrap i {
  position: absolute;
  left: 10px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--tm-muted);
  font-size: 12px;
}

.gtl-search-wrap input {
  width: 100%;
  padding: 7px 10px 7px 30px;
  background: var(--tm-bg2);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius-sm);
  color: var(--tm-text);
  font-size: 12px;
  outline: none;
  transition: border-color var(--tm-transition);
  box-sizing: border-box;
}

.gtl-search-wrap input:focus { border-color: var(--tm-accent); }

.gtl-select {
  background: var(--tm-bg2);
  border: 1px solid var(--tm-border);
  color: var(--tm-text);
  border-radius: var(--tm-radius-sm);
  padding: 6px 10px;
  font-size: 12px;
  outline: none;
  cursor: pointer;
}

.gtl-select:focus { border-color: var(--tm-accent); }

.gtl-toggle-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--tm-muted);
  cursor: pointer;
  white-space: nowrap;
}

.gtl-count-chip {
  font-size: 11px;
  color: var(--tm-accent);
  background: rgba(0,212,255,.1);
  border: 1px solid rgba(0,212,255,.2);
  border-radius: 20px;
  padding: 3px 10px;
  white-space: nowrap;
}

/* Actor table */
.gtl-registry-wrap {
  overflow-x: auto;
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
}

.gtl-actor-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}

.gtl-actor-table thead tr {
  background: var(--tm-bg2);
  border-bottom: 1px solid var(--tm-border);
}

.gtl-actor-table th {
  padding: 10px 12px;
  text-align: left;
  font-size: 11px;
  font-weight: 600;
  color: var(--tm-muted);
  text-transform: uppercase;
  letter-spacing: 0.4px;
  white-space: nowrap;
}

.gtl-actor-row {
  border-bottom: 1px solid var(--tm-border);
  transition: background var(--tm-transition);
  cursor: pointer;
}

.gtl-actor-row:hover { background: rgba(255,255,255,.03); }
.gtl-actor-row.gtl-actor-row-open { background: rgba(0,212,255,.04); }

.gtl-actor-table td { padding: 9px 12px; vertical-align: middle; }

.gtl-actor-name-cell {
  display: flex !important;
  align-items: center;
  gap: 10px;
}

.gtl-actor-icon {
  width: 30px; height: 30px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  flex-shrink: 0;
}

/* Actor expand row */
.gtl-actor-expand-row { background: var(--tm-bg0); }

.gtl-actor-expand-cell {
  padding: 0 !important;
  border-bottom: 2px solid var(--tm-border) !important;
}

/* Actor profile */
.gtl-profile-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  padding: 16px;
  animation: tmFadeIn 0.2s ease;
}

.gtl-profile-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  background: var(--tm-bg1);
  border-radius: var(--tm-radius-sm);
  margin-bottom: 12px;
}

.gtl-profile-name {
  font-size: 15px;
  font-weight: 700;
  color: var(--tm-text);
}

.gtl-profile-aliases {
  font-size: 11px;
  color: var(--tm-muted);
  margin-top: 2px;
}

.gtl-profile-origin {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  color: var(--tm-muted);
}

.gtl-profile-brief {
  font-size: 12px;
  color: var(--tm-muted);
  line-height: 1.6;
  margin: 0 0 12px 0;
}

.gtl-profile-section-title {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--tm-muted);
  margin-bottom: 6px;
  margin-top: 10px;
}

.gtl-profile-section-title:first-child { margin-top: 0; }

.gtl-profile-stats-row {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.gtl-pstat {
  flex: 1;
  min-width: 60px;
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius-sm);
  padding: 8px;
  text-align: center;
  font-size: 10px;
  color: var(--tm-muted);
}

.gtl-pstat div:first-child { margin-bottom: 3px; }

.gtl-op-item {
  font-size: 12px;
  color: var(--tm-text);
  padding: 4px 0;
  border-bottom: 1px solid rgba(30,58,95,.4);
  display: flex;
  align-items: center;
}

/* Chip variations */
.gtl-chip-row { display: flex; flex-wrap: wrap; gap: 5px; }

.gtl-tool-chip, .gtl-ttp-chip, .gtl-target-chip, .gtl-group-chip {
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 3px;
  font-family: monospace;
}

.gtl-tool-chip    { background: rgba(59,130,246,.1);  color: #60a5fa; border: 1px solid rgba(59,130,246,.2); }
.gtl-ttp-chip     { background: rgba(168,85,247,.1);  color: #c084fc; border: 1px solid rgba(168,85,247,.2); }
.gtl-target-chip  { background: rgba(245,158,11,.1);  color: #fbbf24; border: 1px solid rgba(245,158,11,.2); }
.gtl-group-chip   { background: rgba(0,212,255,.08);  color: var(--tm-accent); border: 1px solid rgba(0,212,255,.2); font-size: 11px; padding: 2px 8px; border-radius: 3px; }
.gtl-ioc          { font-size: 10px; padding: 2px 6px; background: rgba(255,45,85,.08); color: #ff6b6b; border: 1px solid rgba(255,45,85,.2); border-radius: 3px; }

.gtl-badge {
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 20px;
  font-weight: 600;
  white-space: nowrap;
}

/* Risk bar */
.gtl-riskbar-wrap {
  display: flex;
  align-items: center;
  gap: 4px;
  height: 16px;
  background: var(--tm-bg3);
  border-radius: 8px;
  overflow: hidden;
  position: relative;
}

.gtl-riskbar {
  height: 100%;
  border-radius: 8px;
  transition: width 0.6s ease;
}

.gtl-riskbar-wrap span {
  position: absolute;
  right: 4px;
  font-size: 10px;
  font-weight: 700;
  color: #fff;
  text-shadow: 0 1px 2px rgba(0,0,0,.5);
  line-height: 16px;
}

/* ── Pulse dot ── */
.gtl-pulse-dot {
  width: 7px; height: 7px;
  border-radius: 50%;
  background: var(--tm-green);
  box-shadow: 0 0 6px var(--tm-green);
  animation: tmPulse 1.4s infinite;
  display: inline-block;
  flex-shrink: 0;
}

/* ── Campaigns panel ── */
.gtl-camps-layout {
  display: grid;
  grid-template-columns: 1fr 260px;
  gap: 16px;
  align-items: start;
}

.gtl-camps-filter-row {
  display: flex;
  gap: 10px;
  align-items: center;
  margin-bottom: 12px;
  flex-wrap: wrap;
}

.gtl-input-sm {
  background: var(--tm-bg2);
  border: 1px solid var(--tm-border);
  color: var(--tm-text);
  border-radius: var(--tm-radius-sm);
  padding: 6px 10px;
  font-size: 12px;
  outline: none;
  flex: 1;
  min-width: 160px;
}

.gtl-input-sm:focus { border-color: var(--tm-accent); }

.gtl-camps-column-header {
  font-size: 12px;
  font-weight: 700;
  margin-bottom: 10px;
  display: flex;
  align-items: center;
  gap: 4px;
}

.gtl-blink { animation: tmBlink 1s infinite; }

.gtl-camp-list { display: flex; flex-direction: column; gap: 8px; }

.gtl-camp-card {
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
  padding: 12px 14px;
  cursor: pointer;
  transition: background var(--tm-transition), transform var(--tm-transition);
}

.gtl-camp-card:hover {
  background: var(--tm-bg2);
  transform: translateX(2px);
}

.gtl-camp-card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 6px;
  gap: 10px;
}

.gtl-camp-name {
  font-size: 13px;
  font-weight: 700;
  color: var(--tm-text);
}

.gtl-camp-actor {
  font-size: 11px;
  color: var(--tm-muted);
  margin-top: 2px;
}

.gtl-camp-meta { display: flex; align-items: center; flex-shrink: 0; }

.gtl-camp-desc {
  font-size: 12px;
  color: var(--tm-muted);
  margin: 0 0 6px 0;
  line-height: 1.5;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.gtl-camp-footer {
  display: flex;
  gap: 14px;
  font-size: 11px;
  color: var(--tm-muted);
  flex-wrap: wrap;
}

/* Sidebar */
.gtl-camps-sidebar, .gtl-sector-sidebar, .gtl-geo-sidebar {
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
  padding: 14px;
  position: sticky;
  top: 0;
}

.gtl-sidebar-title {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--tm-muted);
  margin-bottom: 10px;
  display: flex;
  align-items: center;
  gap: 6px;
}

.gtl-heatmap { display: flex; flex-direction: column; gap: 6px; }

.gtl-heatmap-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 11px;
}

.gtl-heatmap-ttp {
  width: 60px;
  color: var(--tm-muted);
  font-size: 10px;
  flex-shrink: 0;
  font-family: monospace;
}

.gtl-heatmap-bar-wrap {
  flex: 1;
  height: 8px;
  background: var(--tm-bg3);
  border-radius: 4px;
  overflow: hidden;
}

.gtl-heatmap-bar {
  height: 100%;
  border-radius: 4px;
  transition: width 0.5s ease;
}

.gtl-heatmap-count {
  width: 20px;
  text-align: right;
  color: var(--tm-text);
  font-weight: 700;
  font-size: 11px;
}

.gtl-sev-row {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 0;
  border-bottom: 1px solid rgba(30,58,95,.3);
  font-size: 12px;
}

.gtl-sev-row:last-child { border-bottom: none; }

/* ── Vulnerability radar ── */
.gtl-vuln-ticker {
  display: flex;
  align-items: center;
  background: rgba(255,45,85,.06);
  border: 1px solid rgba(255,45,85,.2);
  border-radius: var(--tm-radius-sm);
  padding: 7px 12px;
  margin-bottom: 14px;
  overflow: hidden;
}

.gtl-ticker-track {
  display: flex;
  gap: 40px;
  animation: gtlTickerScroll 30s linear infinite;
  white-space: nowrap;
}

.gtl-ticker-item {
  font-size: 11px;
  white-space: nowrap;
}

@keyframes gtlTickerScroll {
  from { transform: translateX(0); }
  to   { transform: translateX(-50%); }
}

.gtl-vuln-stats-row {
  display: flex;
  gap: 10px;
  margin-bottom: 14px;
  flex-wrap: wrap;
  align-items: flex-end;
}

.gtl-vuln-stat {
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
  padding: 12px 16px;
  text-align: center;
  flex: 1;
  min-width: 100px;
  font-size: 11px;
  color: var(--tm-muted);
}

.gtl-vuln-histogram {
  display: flex;
  align-items: flex-end;
  gap: 12px;
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
  padding: 12px 16px;
  flex: 1;
  min-width: 180px;
}

.gtl-hist-col {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  flex: 1;
}

.gtl-hist-bar-wrap {
  width: 100%;
  height: 60px;
  display: flex;
  align-items: flex-end;
}

.gtl-hist-bar {
  width: 100%;
  border-radius: 3px 3px 0 0;
  transition: height 0.5s ease;
  min-height: 4px;
}

.gtl-vuln-toolbar {
  display: flex;
  gap: 10px;
  align-items: center;
  margin-bottom: 12px;
  flex-wrap: wrap;
}

.gtl-vuln-table-wrap {
  overflow-x: auto;
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
}

.gtl-vuln-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}

.gtl-vuln-table thead tr {
  background: var(--tm-bg2);
  border-bottom: 1px solid var(--tm-border);
}

.gtl-vuln-table th {
  padding: 9px 12px;
  text-align: left;
  font-size: 11px;
  font-weight: 600;
  color: var(--tm-muted);
  text-transform: uppercase;
  letter-spacing: 0.4px;
  white-space: nowrap;
}

.gtl-vuln-row {
  border-bottom: 1px solid var(--tm-border);
  transition: background var(--tm-transition);
}

.gtl-vuln-row:hover { background: rgba(255,255,255,.02); }

.gtl-vuln-table td { padding: 8px 12px; vertical-align: middle; }

.gtl-cve-code {
  font-family: monospace;
  font-size: 11px;
  color: var(--tm-blue);
  background: rgba(59,130,246,.08);
  padding: 2px 6px;
  border-radius: 3px;
}

.gtl-wild-badge {
  font-size: 10px;
  color: var(--tm-crit);
  background: rgba(255,45,85,.1);
  border: 1px solid rgba(255,45,85,.3);
  border-radius: 3px;
  padding: 2px 7px;
  white-space: nowrap;
}

.gtl-zeroday-badge {
  font-size: 9px;
  font-weight: 800;
  color: var(--tm-purple);
  background: rgba(168,85,247,.1);
  border: 1px solid rgba(168,85,247,.3);
  border-radius: 3px;
  padding: 2px 6px;
  letter-spacing: 0.5px;
}

/* ── Sector matrix ── */
.gtl-sector-layout {
  display: grid;
  grid-template-columns: 1fr 240px;
  gap: 16px;
}

.gtl-sector-matrix-wrap {
  overflow: hidden;
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
  padding: 14px;
}

.gtl-matrix-title {
  font-size: 13px;
  font-weight: 700;
  color: var(--tm-text);
  margin-bottom: 12px;
}

.gtl-matrix-scroll { overflow-x: auto; }

.gtl-mx-table {
  border-collapse: separate;
  border-spacing: 2px;
  font-size: 11px;
}

.gtl-mx-corner {
  font-size: 10px;
  color: var(--tm-muted);
  min-width: 110px;
  padding: 4px 6px;
  text-align: left;
}

.gtl-mx-th {
  font-size: 9px;
  color: var(--tm-muted);
  padding: 4px 3px;
  text-align: center;
  min-width: 58px;
  white-space: nowrap;
  letter-spacing: 0;
}

.gtl-mx-label {
  padding: 4px 8px;
  font-size: 11px;
  color: var(--tm-text);
  font-weight: 600;
  min-width: 110px;
  white-space: nowrap;
}

.gtl-mx-cell {
  width: 58px;
  height: 28px;
  text-align: center;
  font-size: 10px;
  font-weight: 700;
  border-radius: 3px;
  cursor: default;
  transition: opacity 0.2s;
}

.gtl-mx-cell:hover { opacity: 1 !important; transform: scale(1.05); }

.gtl-sector-bar-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 7px;
}

.gtl-sector-label {
  font-size: 11px;
  color: var(--tm-text);
  min-width: 100px;
}

.gtl-sector-bar-wrap {
  flex: 1;
  height: 8px;
  background: var(--tm-bg3);
  border-radius: 4px;
  overflow: hidden;
}

.gtl-sector-bar {
  height: 100%;
  border-radius: 4px;
  transition: width 0.6s ease;
}

/* ── Geopolitical ── */
.gtl-geo-layout {
  display: grid;
  grid-template-columns: 220px 1fr;
  gap: 16px;
  align-items: start;
}

.gtl-geo-cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 10px;
}

.gtl-geo-card {
  background: var(--tm-bg1);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius);
  padding: 12px 14px;
  transition: background var(--tm-transition);
}

.gtl-geo-card:hover { background: var(--tm-bg2); }

.gtl-geo-card-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}

.gtl-geo-flag { font-size: 24px; line-height: 1; flex-shrink: 0; }

.gtl-geo-info { flex: 1; min-width: 0; }

.gtl-geo-country { font-weight: 700; font-size: 13px; color: var(--tm-text); }
.gtl-geo-status  { font-size: 11px; margin-top: 1px; }

.gtl-geo-scores  { text-align: center; flex-shrink: 0; }

.gtl-geo-score { font-size: 20px; font-weight: 800; line-height: 1; }

.gtl-geo-escalation {
  padding: 4px 8px;
  border-radius: 4px;
  flex-shrink: 0;
}

.gtl-geo-groups {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-bottom: 8px;
}

.gtl-geo-nexus {
  font-size: 11px;
  color: var(--tm-muted);
  margin-bottom: 6px;
  line-height: 1.5;
}

.gtl-geo-predicted {
  font-size: 11px;
  color: var(--tm-text);
  line-height: 1.5;
  background: rgba(0,212,255,.04);
  padding: 6px 8px;
  border-radius: var(--tm-radius-sm);
  border: 1px solid rgba(0,212,255,.1);
}

.gtl-escl-indicator {
  font-size: 12px;
  line-height: 1.5;
}

/* ── SIGINT feed ── */
.gtl-sigint-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.gtl-sigint-item {
  background: var(--tm-bg2);
  border: 1px solid var(--tm-border);
  border-radius: var(--tm-radius-sm);
  padding: 9px 11px;
  animation: tmFadeIn 0.3s ease;
  transition: background var(--tm-transition);
}

.gtl-sigint-item:hover { background: var(--tm-bg3); }

.gtl-sigint-new { border-color: rgba(0,212,255,.3); animation: tmNewItem 0.5s ease; }

.gtl-sigint-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 5px;
}

.gtl-sigint-priority {
  font-size: 9px;
  font-weight: 800;
  letter-spacing: 0.5px;
  padding: 2px 6px;
  border-radius: 3px;
}

.gtl-sigint-src {
  font-size: 10px;
  font-family: monospace;
}

.gtl-sigint-ts {
  font-size: 10px;
  color: var(--tm-muted);
  margin-left: auto;
}

.gtl-sigint-text {
  font-size: 11px;
  color: var(--tm-text);
  line-height: 1.5;
}

/* ── AI Brief ── */
.gtl-brief-layout {
  display: grid;
  grid-template-columns: 1fr 300px;
  gap: 0;
  height: 100%;
}

.gtl-brief-main {
  display: flex;
  flex-direction: column;
  padding: 18px;
  border-right: 1px solid var(--tm-border);
  overflow-y: auto;
}

.gtl-brief-sigint {
  padding: 18px;
  overflow-y: auto;
  background: var(--tm-bg0);
}

.gtl-brief-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 16px;
  gap: 12px;
  flex-wrap: wrap;
}

.gtl-brief-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--tm-text);
  display: flex;
  align-items: center;
}

.gtl-brief-actions { display: flex; gap: 8px; flex-wrap: wrap; }

.gtl-brief-content {
  flex: 1;
  font-size: 13px;
  line-height: 1.7;
  color: var(--tm-text);
}

.gtl-brief-h2 {
  font-size: 14px;
  font-weight: 800;
  color: var(--tm-text);
  margin: 0 0 6px 0;
  letter-spacing: -0.2px;
}

.gtl-brief-h3 {
  font-size: 12px;
  font-weight: 700;
  color: var(--tm-accent);
  margin: 12px 0 6px 0;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.gtl-brief-li {
  padding: 4px 0 4px 14px;
  border-left: 2px solid var(--tm-border);
  margin-bottom: 4px;
  font-size: 12px;
  color: var(--tm-text);
}

.gtl-brief-li::before {
  content: '›';
  color: var(--tm-accent);
  margin-right: 6px;
  margin-left: -14px;
  font-weight: 700;
}

.gtl-brief-numbered::before {
  content: counter(brief-item) '. ';
  counter-increment: brief-item;
  color: var(--tm-amber);
}

.gtl-brief-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: 16px;
  padding-top: 12px;
  border-top: 1px solid var(--tm-border);
  flex-wrap: wrap;
  gap: 8px;
}

.gtl-brief-sources { display: flex; gap: 6px; flex-wrap: wrap; }

.gtl-source-chip {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 3px;
  background: rgba(99,102,241,.1);
  color: #818cf8;
  border: 1px solid rgba(99,102,241,.2);
  letter-spacing: 0.3px;
}

/* Shared small button */
.gtl-btn-sm {
  font-size: 11px;
  padding: 5px 10px;
  border-radius: var(--tm-radius-sm);
  border: 1px solid var(--tm-border);
  cursor: pointer;
  background: var(--tm-bg2);
  color: var(--tm-text);
  display: inline-flex;
  align-items: center;
  gap: 5px;
  transition: all var(--tm-transition);
  white-space: nowrap;
}

.gtl-btn-sm:hover {
  background: var(--tm-bg3);
  border-color: var(--tm-border2);
}

/* ═══════════════════════════════════════════════════════════════════════════
   SHARED KEYFRAMES
═══════════════════════════════════════════════════════════════════════════ */

@keyframes tmFadeIn {
  from { opacity: 0; transform: translateY(4px); }
  to   { opacity: 1; transform: translateY(0); }
}

@keyframes tmSlideIn {
  from { opacity: 0; transform: translateX(-10px); }
  to   { opacity: 1; transform: translateX(0); }
}

@keyframes tmPopIn {
  from { opacity: 0; transform: scale(0.9); }
  to   { opacity: 1; transform: scale(1); }
}

@keyframes tmPulse {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.4; }
}

@keyframes tmBlink {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0; }
}

@keyframes tmSpin {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}

@keyframes tmNewItem {
  0%   { background: rgba(0,212,255,.15); }
  100% { background: transparent; }
}

/* ═══════════════════════════════════════════════════════════════════════════
   RESPONSIVE
═══════════════════════════════════════════════════════════════════════════ */

@media (max-width: 1100px) {
  .gtl-worldmap-grid  { grid-template-columns: 1fr; }
  .gtl-map-sigint-col { max-height: 300px; }
  .gtl-brief-layout   { grid-template-columns: 1fr; }
  .gtl-brief-sigint   { display: none; }
  .gtl-geo-layout     { grid-template-columns: 1fr; }
  .gtl-sector-layout  { grid-template-columns: 1fr; }
  .gtl-camps-layout   { grid-template-columns: 1fr; }
}

@media (max-width: 800px) {
  .gtl-tabs .gtl-tab span { display: none; }
  .gtl-tabs .gtl-tab       { padding: 10px 12px; }
  .gtl-geo-cards { grid-template-columns: 1fr; }
  .gtl-profile-grid { grid-template-columns: 1fr; }
  .tgv2-lens-panel { width: 100%; border-radius: 0; }
  .tgv2-right-panel { width: 280px; }
}
"""

out = '/home/user/webapp/css/threat-modules-v2.css'
with open(out, 'w') as f:
    f.write(CSS)

import os
lines = CSS.count('\n') + 1
size  = os.path.getsize(out)
print(f"threat-modules-v2.css: {lines} lines ({size:,} bytes)")
