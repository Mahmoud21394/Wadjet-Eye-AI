css = r"""/* ══════════════════════════════════════════════════════════════════════════
   Wadjet-Eye AI v25.0 — CDWIE v2.0 Stylesheet
   Prefix: v2-   |   Companion to js/darkweb-cdwie-v2.js
   Design tokens: inherits from platform-v20.css / p19
   ══════════════════════════════════════════════════════════════════════════ */

/* ─────────────────────────── KEYFRAMES ──────────────────────────────────── */
@keyframes v2fadeIn   { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:none} }
@keyframes v2slideIn  { from{opacity:0;transform:translateX(-10px)} to{opacity:1;transform:none} }
@keyframes v2popIn    { from{opacity:0;transform:scale(.88)} 70%{transform:scale(1.04)} to{opacity:1;transform:scale(1)} }
@keyframes v2spin     { to{transform:rotate(360deg)} }
@keyframes v2pulse    { 0%,100%{opacity:1} 50%{opacity:.45} }
@keyframes v2barFill  { from{width:0} to{width:var(--bar-w,100%)} }
@keyframes v2countUp  { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:none} }
@keyframes v2glow     { 0%,100%{box-shadow:0 0 0 transparent} 50%{box-shadow:0 0 18px rgba(99,102,241,.35)} }
@keyframes v2dotBlink { 0%,100%{opacity:1} 50%{opacity:.2} }
@keyframes v2laserSwp { from{left:-100%} to{left:200%} }
@keyframes v2toast    { 0%{opacity:0;transform:translateX(100%)} 10%{opacity:1;transform:none}
                         80%{opacity:1;transform:none} 100%{opacity:0;transform:translateX(100%)} }

/* ─────────────────────────── ROOT SHELL ─────────────────────────────────── */
.v2-root {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  background: #020817;
  color: #e2e8f0;
  font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  overflow: hidden;
  position: relative;
  font-size: 13px;
  line-height: 1.5;
}

/* ─────────────────────────── KPI BAR ────────────────────────────────────── */
.v2-kpi-bar {
  display: flex;
  align-items: stretch;
  background: linear-gradient(135deg, #06101f, #0a1628);
  border-bottom: 1px solid rgba(255,255,255,.07);
  flex-shrink: 0;
  overflow-x: auto;
  position: relative;
  scrollbar-width: none;
}
.v2-kpi-bar::-webkit-scrollbar { display: none; }
.v2-kpi-bar::after {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, transparent, rgba(34,211,238,.03), transparent);
  animation: v2laserSwp 7s linear infinite;
  pointer-events: none;
}
.v2-kpi-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 10px 22px;
  border-right: 1px solid rgba(255,255,255,.06);
  min-width: 108px;
  flex-shrink: 0;
  gap: 2px;
  transition: background .2s;
  cursor: default;
  position: relative;
}
.v2-kpi-item:hover { background: rgba(255,255,255,.03); }
.v2-kpi-icon {
  font-size: 13px;
  opacity: .7;
  margin-bottom: 2px;
}
.v2-kpi-val {
  font-size: 19px;
  font-weight: 800;
  line-height: 1;
  letter-spacing: -.02em;
  animation: v2countUp .6s ease both;
}
.v2-kpi-label {
  font-size: 9px;
  font-weight: 600;
  letter-spacing: .08em;
  text-transform: uppercase;
  color: #475569;
}
/* KPI color variants */
.v2-kpi-cyan   { color: #22d3ee; }
.v2-kpi-purple { color: #a855f7; }
.v2-kpi-blue   { color: #3b82f6; }
.v2-kpi-orange { color: #f97316; }
.v2-kpi-green  { color: #22c55e; }
.v2-kpi-teal   { color: #14b8a6; }
.v2-kpi-yellow { color: #f59e0b; }

/* ─────────────────────────── HEADER ─────────────────────────────────────── */
.v2-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 24px 12px;
  background: linear-gradient(135deg, #06101f, #0a1628 60%, #08122a);
  border-bottom: 1px solid rgba(255,255,255,.07);
  flex-shrink: 0;
  gap: 20px;
  flex-wrap: wrap;
}
.v2-header-left {
  display: flex;
  align-items: center;
  gap: 14px;
  min-width: 0;
}
.v2-header-icon {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  background: rgba(99,102,241,.15);
  border: 1px solid rgba(99,102,241,.3);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
  color: #6366f1;
  flex-shrink: 0;
  animation: v2glow 3.5s ease infinite;
}
.v2-header-title {
  font-size: 14px;
  font-weight: 800;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: #f1f5f9;
  display: flex;
  align-items: center;
  gap: 8px;
}
.v2-version-badge {
  font-size: 10px;
  font-weight: 700;
  background: rgba(99,102,241,.25);
  color: #818cf8;
  border: 1px solid rgba(99,102,241,.4);
  border-radius: 6px;
  padding: 1px 7px;
  letter-spacing: .04em;
}
.v2-header-sub {
  font-size: 11px;
  color: #64748b;
  margin-top: 3px;
  transition: opacity .3s;
  letter-spacing: .02em;
}
.v2-header-right {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}
.v2-status-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: .08em;
  text-transform: uppercase;
  color: #22c55e;
  background: rgba(34,197,94,.1);
  border: 1px solid rgba(34,197,94,.25);
  border-radius: 20px;
  padding: 2px 9px;
}
.v2-status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #22c55e;
  animation: v2dotBlink 1.6s ease infinite;
}
.v2-live-ts {
  color: #475569;
  font-size: 10px;
}

/* ─────────────────────────── TABS ───────────────────────────────────────── */
.v2-tabs {
  display: flex;
  background: #060f1e;
  border-bottom: 1px solid rgba(255,255,255,.06);
  flex-shrink: 0;
  overflow-x: auto;
  scrollbar-width: none;
  gap: 0;
}
.v2-tabs::-webkit-scrollbar { display: none; }
.v2-tab {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 10px 16px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: .04em;
  color: #64748b;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  white-space: nowrap;
  flex-shrink: 0;
  transition: color .2s, border-color .2s, background .2s;
  position: relative;
}
.v2-tab:hover {
  color: #94a3b8;
  background: rgba(255,255,255,.03);
}
.v2-tab.active {
  color: var(--tab-color, #6366f1);
  border-bottom-color: var(--tab-color, #6366f1);
  background: rgba(255,255,255,.03);
}
.v2-tab-badge {
  font-size: 9px;
  font-weight: 700;
  padding: 1px 5px;
  border-radius: 8px;
  background: rgba(255,255,255,.08);
  color: #94a3b8;
  letter-spacing: .02em;
}
.v2-tab.active .v2-tab-badge {
  background: rgba(99,102,241,.25);
  color: var(--tab-color, #818cf8);
}

/* ─────────────────────────── ENGINE PANEL ───────────────────────────────── */
.v2-engine-panel {
  flex: 1;
  min-height: 0;
  overflow: hidden;
  position: relative;
}
.v2-engine {
  height: 100%;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 20px 24px;
  animation: v2fadeIn .25s ease both;
  scrollbar-width: thin;
  scrollbar-color: #1e293b transparent;
}
.v2-engine::-webkit-scrollbar { width: 4px; }
.v2-engine::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }

/* ─────────────────────────── SHARED COMPONENTS ──────────────────────────── */

/* Badges */
.v2-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: .04em;
  text-transform: uppercase;
  padding: 2px 7px;
  border-radius: 5px;
  background: rgba(255,255,255,.08);
  color: #94a3b8;
  white-space: nowrap;
  flex-shrink: 0;
}
.v2-badge-critical { background: rgba(239,68,68,.18);  color: #f87171; }
.v2-badge-high     { background: rgba(249,115,22,.18); color: #fb923c; }
.v2-badge-medium   { background: rgba(234,179,8,.18);  color: #facc15; }
.v2-badge-low      { background: rgba(34,197,94,.15);  color: #4ade80; }
.v2-badge-blue     { background: rgba(59,130,246,.18); color: #60a5fa; }
.v2-badge-purple   { background: rgba(168,85,247,.18); color: #c084fc; }
.v2-badge-orange   { background: rgba(249,115,22,.18); color: #fb923c; }
.v2-badge-green    { background: rgba(34,197,94,.15);  color: #4ade80; }
.v2-badge-teal     { background: rgba(20,184,166,.15); color: #2dd4bf; }
.v2-badge-yellow   { background: rgba(234,179,8,.15);  color: #facc15; }

/* Buttons */
.v2-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 7px 14px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: .02em;
  border: 1px solid transparent;
  cursor: pointer;
  transition: all .18s ease;
  white-space: nowrap;
  flex-shrink: 0;
}
.v2-btn:active { transform: scale(.96); }
.v2-btn-primary {
  background: linear-gradient(135deg, #4f46e5, #7c3aed);
  color: #fff;
  border-color: rgba(99,102,241,.5);
  box-shadow: 0 2px 12px rgba(99,102,241,.3);
}
.v2-btn-primary:hover {
  background: linear-gradient(135deg, #4338ca, #6d28d9);
  box-shadow: 0 4px 18px rgba(99,102,241,.45);
  transform: translateY(-1px);
}
.v2-btn-ghost {
  background: rgba(255,255,255,.05);
  color: #94a3b8;
  border-color: rgba(255,255,255,.1);
}
.v2-btn-ghost:hover {
  background: rgba(255,255,255,.1);
  color: #f1f5f9;
  border-color: rgba(255,255,255,.2);
}

/* Chips (clickable suggestion pills) */
.v2-chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 10px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 500;
  background: rgba(255,255,255,.06);
  color: #94a3b8;
  border: 1px solid rgba(255,255,255,.1);
  cursor: pointer;
  transition: all .15s;
  white-space: nowrap;
}
.v2-chip:hover {
  background: rgba(99,102,241,.18);
  color: #a5b4fc;
  border-color: rgba(99,102,241,.4);
}

/* IOC code tag */
.v2-ioc-tag {
  display: inline-block;
  font-family: 'JetBrains Mono', 'Fira Code', Consolas, monospace;
  font-size: 10px;
  background: rgba(34,211,238,.08);
  color: #67e8f9;
  border: 1px solid rgba(34,211,238,.2);
  border-radius: 4px;
  padding: 1px 6px;
  user-select: all;
}

/* Empty state */
.v2-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 20px;
  color: #334155;
  font-size: 13px;
  text-align: center;
  gap: 8px;
}

/* Loading */
.v2-loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
  padding: 60px 20px;
}
.v2-spinner {
  width: 28px;
  height: 28px;
  border: 3px solid #1e293b;
  border-top-color: #6366f1;
  border-radius: 50%;
  animation: v2spin .8s linear infinite;
  flex-shrink: 0;
}

/* Dim / muted text */
.v2-dim { color: #334155; font-size: 12px; }

/* Toast notification */
.v2-toast {
  position: fixed;
  bottom: 28px;
  right: 28px;
  z-index: 99999;
  background: #0f172a;
  border: 1px solid rgba(255,255,255,.12);
  border-radius: 10px;
  padding: 12px 18px;
  font-size: 12px;
  color: #e2e8f0;
  display: flex;
  align-items: center;
  gap: 8px;
  box-shadow: 0 8px 40px rgba(0,0,0,.7);
  animation: v2toast 3s ease forwards;
  pointer-events: none;
  max-width: 320px;
}

/* Graph utility classes */
.v2-graph-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 0 12px;
  flex-wrap: wrap;
}
.v2-graph-title {
  font-size: 13px;
  font-weight: 700;
  color: #94a3b8;
  display: flex;
  align-items: center;
  gap: 6px;
}
.v2-graph-btn {
  width: 30px;
  height: 30px;
  border-radius: 7px;
  background: rgba(255,255,255,.06);
  border: 1px solid rgba(255,255,255,.1);
  color: #64748b;
  font-size: 12px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all .15s;
}
.v2-graph-btn:hover {
  background: rgba(255,255,255,.12);
  color: #f1f5f9;
  border-color: rgba(255,255,255,.2);
}
.v2-graph-select {
  background: #0a1628;
  border: 1px solid rgba(255,255,255,.1);
  color: #94a3b8;
  font-size: 11px;
  padding: 4px 8px;
  border-radius: 7px;
  cursor: pointer;
  outline: none;
  transition: border-color .15s;
}
.v2-graph-select:hover,
.v2-graph-select:focus { border-color: rgba(99,102,241,.4); }
.v2-graph-legend {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 10px;
  color: #64748b;
  margin-left: 4px;
}
.v2-graph-legend span {
  display: flex;
  align-items: center;
  gap: 4px;
}
.v2-graph-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  display: inline-block;
  flex-shrink: 0;
}
.v2-graph-tooltip {
  position: fixed;
  z-index: 9999;
  pointer-events: none;
  background: #0f172a;
  border: 1px solid #1e293b;
  border-radius: 8px;
  padding: 8px 12px;
  font-size: 12px;
  color: #e2e8f0;
  box-shadow: 0 4px 24px rgba(0,0,0,.7);
}

/* WS indicator dot */
.v2-ws-dot {
  display: inline-block;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #475569;
  transition: background .4s;
  flex-shrink: 0;
}
.v2-ws-dot.connected    { background: #22c55e; box-shadow: 0 0 6px #22c55e88; }
.v2-ws-dot.disconnected { background: #ef4444; }

/* TLP badge */
.v2-tlp-badge {
  font-size: 10px;
  font-weight: 800;
  letter-spacing: .08em;
  padding: 3px 10px;
  border-radius: 6px;
  text-transform: uppercase;
}

/* ─────────────────────────── COGNITIVE SEARCH ───────────────────────────── */
.v2-search-hero {
  max-width: 760px;
  margin: 0 auto 28px;
  text-align: center;
  padding: 16px 0 0;
}
.v2-search-icon {
  width: 60px;
  height: 60px;
  border-radius: 16px;
  background: rgba(34,211,238,.1);
  border: 1px solid rgba(34,211,238,.25);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 26px;
  color: #22d3ee;
  margin: 0 auto 14px;
  animation: v2glow 3.5s ease infinite;
}
.v2-search-title {
  font-size: 20px;
  font-weight: 800;
  color: #f1f5f9;
  margin: 0 0 6px;
}
.v2-search-sub {
  font-size: 12px;
  color: #64748b;
  margin: 0 0 18px;
  line-height: 1.6;
}
.v2-search-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  background: #060f1e;
  border: 1px solid rgba(255,255,255,.12);
  border-radius: 12px;
  padding: 6px 6px 6px 14px;
  transition: border-color .2s, box-shadow .2s;
}
.v2-search-bar:focus-within {
  border-color: rgba(34,211,238,.4);
  box-shadow: 0 0 0 3px rgba(34,211,238,.08);
}
.v2-search-ico { color: #475569; font-size: 14px; flex-shrink: 0; }
.v2-search-input {
  flex: 1;
  background: none;
  border: none;
  outline: none;
  color: #f1f5f9;
  font-size: 13px;
  font-family: inherit;
  caret-color: #22d3ee;
}
.v2-search-input::placeholder { color: #334155; }
.v2-search-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  justify-content: center;
  margin-top: 12px;
}
.v2-search-filters {
  display: flex;
  gap: 6px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}
.v2-filter-btn {
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 600;
  background: rgba(255,255,255,.05);
  border: 1px solid rgba(255,255,255,.1);
  color: #64748b;
  cursor: pointer;
  transition: all .15s;
}
.v2-filter-btn:hover,
.v2-filter-btn.active {
  background: rgba(99,102,241,.18);
  color: #a5b4fc;
  border-color: rgba(99,102,241,.4);
}
.v2-search-steps {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 16px 0 8px;
  max-width: 420px;
  margin: 0 auto;
}
.v2-search-step {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: #64748b;
  animation: v2slideIn .3s ease both;
}
.v2-results-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
  padding: 0 2px;
}
.v2-results-ai-badge {
  font-size: 10px;
  font-weight: 700;
  padding: 3px 9px;
  border-radius: 20px;
  background: rgba(99,102,241,.15);
  color: #818cf8;
  display: flex;
  align-items: center;
  gap: 5px;
}
.v2-result-card {
  background: rgba(10,22,40,.7);
  border: 1px solid rgba(255,255,255,.06);
  border-left: 3px solid var(--rc, #6366f1);
  border-radius: 10px;
  padding: 14px 16px;
  margin-bottom: 10px;
  cursor: pointer;
  transition: all .18s;
  animation: v2fadeIn .3s ease both;
  position: relative;
  overflow: hidden;
}
.v2-result-card::before {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, var(--rc,#6366f1) 0%, transparent 60%);
  opacity: 0;
  transition: opacity .2s;
}
.v2-result-card:hover {
  border-color: rgba(255,255,255,.14);
  background: rgba(15,30,55,.9);
  transform: translateX(2px);
}
.v2-result-card:hover::before { opacity: .03; }
.v2-result-type {
  font-size: 10px;
  font-weight: 700;
  letter-spacing: .07em;
  text-transform: uppercase;
  color: #475569;
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 5px;
}
.v2-result-relevance {
  position: absolute;
  top: 14px;
  right: 16px;
  font-size: 12px;
  font-weight: 800;
  color: #22c55e;
}
.v2-result-title {
  font-size: 14px;
  font-weight: 700;
  color: #f1f5f9;
  margin: 0 0 5px;
  padding-right: 52px;
}
.v2-result-summary {
  font-size: 12px;
  color: #94a3b8;
  margin: 0 0 8px;
  line-height: 1.6;
}
.v2-result-iocs {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-bottom: 8px;
}
.v2-result-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

/* ─────────────────────────── THREAT ACTOR DNA ───────────────────────────── */
.v2-actor-layout {
  display: grid;
  grid-template-columns: 220px 1fr;
  gap: 0;
  height: calc(100vh - 200px);
  min-height: 500px;
  max-height: 800px;
}
.v2-actor-roster {
  background: #060f1e;
  border-right: 1px solid rgba(255,255,255,.07);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.v2-roster-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 14px;
  border-bottom: 1px solid rgba(255,255,255,.06);
  flex-shrink: 0;
}
.v2-roster-title {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .05em;
  color: #64748b;
  text-transform: uppercase;
  display: flex;
  align-items: center;
  gap: 6px;
}
.v2-actor-list {
  flex: 1;
  overflow-y: auto;
  padding: 6px;
  scrollbar-width: thin;
  scrollbar-color: #1e293b transparent;
}
.v2-actor-list::-webkit-scrollbar { width: 3px; }
.v2-actor-list::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 3px; }
.v2-actor-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 10px;
  border-radius: 8px;
  cursor: pointer;
  transition: all .15s;
  border: 1px solid transparent;
  margin-bottom: 2px;
}
.v2-actor-row:hover {
  background: rgba(255,255,255,.04);
  border-color: rgba(255,255,255,.08);
}
.v2-actor-row.active {
  background: rgba(99,102,241,.12);
  border-color: rgba(99,102,241,.3);
}
.v2-actor-avatar {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
  flex-shrink: 0;
}
.v2-actor-info { flex: 1; min-width: 0; }
.v2-actor-name {
  font-size: 12px;
  font-weight: 700;
  color: #f1f5f9;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.v2-actor-alias {
  font-size: 10px;
  color: #475569;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.v2-actor-detail {
  overflow-y: auto;
  overflow-x: hidden;
  scrollbar-width: thin;
  scrollbar-color: #1e293b transparent;
  padding: 0;
}
.v2-actor-detail::-webkit-scrollbar { width: 4px; }
.v2-actor-detail::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }

/* Actor Profile */
.v2-actor-profile { padding: 20px; }
.v2-actor-profile-header {
  display: flex;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}
.v2-actor-avatar-lg {
  width: 52px;
  height: 52px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 22px;
  flex-shrink: 0;
  border: 1px solid rgba(255,255,255,.1);
}
.v2-actor-profile-meta { flex: 1; min-width: 0; }
.v2-actor-profile-name {
  font-size: 18px;
  font-weight: 800;
  color: #f1f5f9;
  margin: 0 0 4px;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.v2-actor-profile-aliases {
  font-size: 11px;
  color: #475569;
  margin-bottom: 6px;
  line-height: 1.6;
}
.v2-actor-profile-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}
.v2-actor-stats {
  display: flex;
  gap: 10px;
  flex-shrink: 0;
}
.v2-stat-chip {
  display: flex;
  flex-direction: column;
  align-items: center;
  background: rgba(255,255,255,.04);
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 8px;
  padding: 8px 14px;
  min-width: 52px;
  text-align: center;
}
.v2-stat-val {
  font-size: 18px;
  font-weight: 800;
  color: #f1f5f9;
  line-height: 1;
}
.v2-stat-lbl {
  font-size: 9px;
  color: #475569;
  letter-spacing: .05em;
  text-transform: uppercase;
  margin-top: 3px;
}

/* Attribution signal bars */
.v2-attr-section {
  background: rgba(255,255,255,.02);
  border: 1px solid rgba(255,255,255,.06);
  border-radius: 10px;
  padding: 14px;
  margin-bottom: 14px;
}
.v2-attr-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 7px;
}
.v2-attr-row:last-child { margin-bottom: 0; }
.v2-attr-label {
  font-size: 11px;
  color: #64748b;
  min-width: 100px;
}
.v2-attr-bar-wrap {
  flex: 1;
  height: 6px;
  background: rgba(255,255,255,.06);
  border-radius: 3px;
  overflow: hidden;
}
.v2-attr-bar {
  height: 100%;
  border-radius: 3px;
  animation: v2barFill .6s ease both;
  transition: width .4s ease;
}
.v2-attr-val {
  font-size: 11px;
  font-weight: 700;
  color: #94a3b8;
  min-width: 34px;
  text-align: right;
}
.v2-attr-weight {
  font-size: 9px;
  color: #334155;
  min-width: 42px;
}

/* DNA sub-tabs */
.v2-dna-tabs {
  display: flex;
  gap: 4px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}
.v2-dna-tab {
  display: flex;
  align-items: center;
  gap: 5px;
  padding: 6px 12px;
  border-radius: 8px;
  font-size: 11px;
  font-weight: 600;
  background: rgba(255,255,255,.04);
  border: 1px solid rgba(255,255,255,.08);
  color: #64748b;
  cursor: pointer;
  transition: all .15s;
}
.v2-dna-tab:hover {
  background: rgba(255,255,255,.08);
  color: #94a3b8;
}
.v2-dna-tab.active {
  background: rgba(99,102,241,.18);
  border-color: rgba(99,102,241,.4);
  color: #a5b4fc;
}
.v2-dna-content {
  animation: v2fadeIn .2s ease both;
}

/* DNA Overview */
.v2-dna-overview { }
.v2-actor-desc {
  font-size: 12px;
  color: #94a3b8;
  line-height: 1.7;
  margin-bottom: 14px;
  padding: 12px;
  background: rgba(255,255,255,.02);
  border-left: 3px solid rgba(99,102,241,.4);
  border-radius: 0 8px 8px 0;
}
.v2-ov-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 8px;
  margin-bottom: 14px;
}
.v2-ov-item {
  display: flex;
  flex-direction: column;
  gap: 3px;
  padding: 10px 12px;
  background: rgba(255,255,255,.02);
  border: 1px solid rgba(255,255,255,.06);
  border-radius: 8px;
}
.v2-ov-lbl {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .05em;
  text-transform: uppercase;
  color: #475569;
  display: flex;
  align-items: center;
  gap: 5px;
}
.v2-ov-val {
  font-size: 12px;
  color: #cbd5e1;
  font-weight: 500;
}
.v2-ov-sectors {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.v2-ov-sectors .v2-ov-lbl { margin-bottom: 4px; }
.v2-ov-sectors > div { display: flex; flex-wrap: wrap; gap: 5px; }

/* DNA Behavior */
.v2-dna-behavior {
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
}
.v2-radar-wrap {
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
}
.v2-beh-bars { flex: 1; min-width: 200px; }
.v2-beh-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.v2-beh-lbl {
  font-size: 11px;
  color: #64748b;
  min-width: 110px;
  text-transform: capitalize;
}
.v2-beh-bar-wrap {
  flex: 1;
  height: 6px;
  background: rgba(255,255,255,.06);
  border-radius: 3px;
  overflow: hidden;
}
.v2-beh-bar {
  height: 100%;
  border-radius: 3px;
  animation: v2barFill .6s ease both;
  transition: width .4s ease;
}
.v2-beh-val {
  font-size: 11px;
  font-weight: 700;
  color: #94a3b8;
  min-width: 26px;
  text-align: right;
}

/* DNA TTPs */
.v2-mitre-grid { display: flex; flex-direction: column; gap: 6px; }
.v2-mitre-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 12px;
  background: rgba(255,255,255,.02);
  border: 1px solid rgba(255,255,255,.05);
  border-radius: 8px;
  transition: background .15s;
}
.v2-mitre-row:hover { background: rgba(255,255,255,.04); }
.v2-mitre-id {
  font-family: 'JetBrains Mono', Consolas, monospace;
  font-size: 11px;
  color: #67e8f9;
  min-width: 80px;
}
.v2-mitre-name { font-size: 12px; color: #cbd5e1; flex: 1; }

/* DNA Infra */
.v2-dna-infra { display: flex; flex-direction: column; gap: 14px; }
.v2-infra-sect {
  padding: 12px 14px;
  background: rgba(255,255,255,.02);
  border: 1px solid rgba(255,255,255,.06);
  border-radius: 8px;
}
.v2-infra-sect h4 {
  font-size: 11px;
  font-weight: 700;
  color: #64748b;
  margin: 0 0 8px;
  display: flex;
  align-items: center;
  gap: 6px;
  text-transform: uppercase;
  letter-spacing: .05em;
}
.v2-infra-sect > div { display: flex; flex-wrap: wrap; gap: 5px; }

/* DNA Timeline */
.v2-dna-timeline { }
.v2-tl-line {
  display: flex;
  flex-direction: column;
  gap: 0;
  border-left: 2px solid rgba(255,255,255,.1);
  margin-left: 10px;
  padding-left: 0;
}
.v2-tl-item {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 10px 0 10px 18px;
  position: relative;
  animation: v2slideIn .3s ease both;
}
.v2-tl-dot {
  position: absolute;
  left: -6px;
  top: 16px;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
  border: 2px solid #020817;
}
.v2-tl-body { flex: 1; min-width: 0; }
.v2-tl-date {
  font-size: 10px;
  font-weight: 800;
  letter-spacing: .06em;
  color: #475569;
  text-transform: uppercase;
  margin-bottom: 3px;
}
.v2-tl-event {
  font-size: 12px;
  color: #cbd5e1;
  line-height: 1.5;
}

/* ─────────────────────────── KNOWLEDGE GRAPH ────────────────────────────── */
/* (canvas + toolbar — toolbar styles already in .v2-graph-toolbar above) */

/* ─────────────────────────── NEURAL CORRELATOR ──────────────────────────── */
.v2-nc-layout {
  display: grid;
  grid-template-columns: 1fr 320px;
  gap: 16px;
  margin-bottom: 16px;
}
.v2-nc-panel {
  background: rgba(10,22,40,.6);
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 12px;
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.v2-nc-header {
  font-size: 13px;
  font-weight: 700;
  color: #f1f5f9;
  display: flex;
  align-items: center;
  gap: 8px;
}
.v2-nc-subtitle {
  font-size: 11px;
  color: #64748b;
  line-height: 1.6;
}
.v2-nc-detail-panel {
  background: rgba(10,22,40,.6);
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 12px;
  padding: 16px;
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: #1e293b transparent;
}
.v2-nc-detail-panel::-webkit-scrollbar { width: 3px; }
.v2-nc-detail-panel::-webkit-scrollbar-thumb { background: #1e293b; }
.v2-nc-placeholder {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  min-height: 200px;
  text-align: center;
  color: #334155;
  font-size: 12px;
  line-height: 1.7;
}
.v2-nc-detail-inner { display: flex; flex-direction: column; gap: 14px; }
.v2-nc-detail-title {
  font-size: 13px;
  font-weight: 700;
  color: #f1f5f9;
  padding-bottom: 8px;
  border-bottom: 1px solid rgba(255,255,255,.06);
}
.v2-nc-actors-row {
  display: flex;
  align-items: center;
  gap: 12px;
  justify-content: center;
}
.v2-nc-actor-block {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 12px 16px;
  border-radius: 10px;
  border: 2px solid rgba(255,255,255,.1);
  font-size: 11px;
  font-weight: 700;
  color: #f1f5f9;
  text-align: center;
  min-width: 80px;
  transition: border-color .2s;
}
.v2-nc-score-display {
  font-size: 24px;
  font-weight: 800;
  text-align: center;
  flex-shrink: 0;
  line-height: 1.1;
}
.v2-nc-section { }
.v2-nc-section h4 {
  font-size: 10px;
  font-weight: 700;
  color: #475569;
  text-transform: uppercase;
  letter-spacing: .06em;
  margin: 0 0 8px;
}
.v2-nc-shared-item {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 11px;
  color: #94a3b8;
  padding: 4px 0;
}
.v2-nc-assess {
  font-size: 12px;
  color: #94a3b8;
  line-height: 1.7;
  padding: 10px 12px;
  background: rgba(255,255,255,.02);
  border-left: 3px solid rgba(236,72,153,.4);
  border-radius: 0 8px 8px 0;
}

/* Correlation edge list */
.v2-nc-edge-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 8px;
}
.v2-nc-edge-card {
  background: rgba(10,22,40,.6);
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 10px;
  padding: 12px 14px;
  cursor: pointer;
  transition: all .18s;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.v2-nc-edge-card:hover {
  background: rgba(20,40,70,.8);
  border-color: rgba(236,72,153,.3);
  transform: translateY(-1px);
}
.v2-nc-edge-card.active {
  border-color: rgba(236,72,153,.5);
  background: rgba(236,72,153,.06);
}
.v2-nc-edge-actors {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.v2-nc-actor-chip {
  font-size: 11px;
  font-weight: 700;
  padding: 3px 9px;
  border-radius: 6px;
}
.v2-nc-edge-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.v2-nc-score {
  font-size: 12px;
  font-weight: 700;
}

/* ─────────────────────────── KILL CHAIN TRACKER ─────────────────────────── */
.v2-kc-layout {
  display: grid;
  grid-template-columns: 220px 1fr;
  gap: 0;
  min-height: 500px;
}
.v2-kc-nav {
  background: #060f1e;
  border-right: 1px solid rgba(255,255,255,.07);
  padding: 12px 8px;
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: #1e293b transparent;
}
.v2-kc-nav::-webkit-scrollbar { width: 3px; }
.v2-kc-nav::-webkit-scrollbar-thumb { background: #1e293b; }
.v2-kc-nav-title {
  font-size: 10px;
  font-weight: 700;
  letter-spacing: .07em;
  text-transform: uppercase;
  color: #475569;
  padding: 4px 8px 10px;
  display: flex;
  align-items: center;
  gap: 6px;
}
.v2-kc-nav-item {
  padding: 10px 10px;
  border-radius: 8px;
  cursor: pointer;
  transition: all .15s;
  border: 1px solid transparent;
  margin-bottom: 2px;
}
.v2-kc-nav-item:hover {
  background: rgba(255,255,255,.04);
  border-color: rgba(255,255,255,.07);
}
.v2-kc-nav-item.active {
  background: rgba(249,115,22,.1);
  border-color: rgba(249,115,22,.3);
}
.v2-kc-nav-name {
  font-size: 12px;
  font-weight: 600;
  color: #f1f5f9;
  margin-bottom: 4px;
}
.v2-kc-nav-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}
.v2-kc-main {
  padding: 20px 24px;
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: #1e293b transparent;
}
.v2-kc-main::-webkit-scrollbar { width: 4px; }
.v2-kc-main::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }
.v2-kc-header { margin-bottom: 20px; }
.v2-kc-campaign-name {
  font-size: 20px;
  font-weight: 800;
  color: #f1f5f9;
  margin-bottom: 8px;
}
.v2-kc-campaign-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 6px;
}
.v2-kc-group {
  font-size: 12px;
  color: #64748b;
  display: flex;
  align-items: center;
  gap: 5px;
}

/* Kill chain stages */
.v2-kc-chain {
  display: flex;
  align-items: flex-start;
  gap: 0;
  overflow-x: auto;
  padding-bottom: 16px;
  margin-bottom: 20px;
  scrollbar-width: thin;
  scrollbar-color: #1e293b transparent;
}
.v2-kc-chain::-webkit-scrollbar { height: 3px; }
.v2-kc-chain::-webkit-scrollbar-thumb { background: #1e293b; }
.v2-stage {
  display: flex;
  flex-direction: column;
  align-items: center;
  min-width: 130px;
  padding: 12px 8px;
  background: rgba(10,22,40,.6);
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 10px;
  text-align: center;
  flex-shrink: 0;
  transition: all .2s;
}
.v2-stage-arrow {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  color: #334155;
  font-size: 14px;
  flex-shrink: 0;
  margin-top: 32px;
}
.v2-stage-icon {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  background: rgba(255,255,255,.06);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 15px;
  color: #64748b;
  margin-bottom: 8px;
  transition: all .2s;
}
.v2-stage-name {
  font-size: 11px;
  font-weight: 700;
  color: #94a3b8;
  margin-bottom: 6px;
}
.v2-stage-ttps {
  display: flex;
  flex-wrap: wrap;
  gap: 3px;
  justify-content: center;
  margin-bottom: 6px;
}
.v2-stage-eta-badge {
  font-size: 9px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 4px;
  background: rgba(255,255,255,.06);
  color: #64748b;
}
/* Stage states */
.v2-stage-done {
  background: rgba(34,197,94,.06);
  border-color: rgba(34,197,94,.2);
}
.v2-stage-done .v2-stage-icon {
  background: rgba(34,197,94,.15);
  color: #4ade80;
}
.v2-stage-done .v2-stage-name { color: #4ade80; }
.v2-stage-eta-done {
  background: rgba(34,197,94,.12);
  color: #4ade80;
}
.v2-stage-current {
  background: rgba(249,115,22,.08);
  border-color: rgba(249,115,22,.4);
  box-shadow: 0 0 16px rgba(249,115,22,.15);
  animation: v2glow 2s ease infinite;
}
.v2-stage-current .v2-stage-icon {
  background: rgba(249,115,22,.2);
  color: #fb923c;
}
.v2-stage-current .v2-stage-name { color: #fb923c; }
.v2-stage-eta-current {
  background: rgba(249,115,22,.15);
  color: #fb923c;
}
.v2-stage-future { opacity: .55; }
.v2-stage-confirmed {
  background: rgba(34,197,94,.04);
  border-color: rgba(34,197,94,.15);
}

/* Kill chain defenses */
.v2-kc-defenses {
  background: rgba(255,255,255,.02);
  border: 1px solid rgba(255,255,255,.06);
  border-radius: 10px;
  padding: 14px 16px;
}
.v2-kc-def-title {
  font-size: 11px;
  font-weight: 700;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: .06em;
  margin-bottom: 10px;
  display: flex;
  align-items: center;
  gap: 6px;
}
.v2-defense-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 7px 0;
  border-bottom: 1px solid rgba(255,255,255,.04);
  font-size: 12px;
  color: #94a3b8;
  line-height: 1.5;
}
.v2-defense-item:last-child { border-bottom: none; }
.v2-defense-num {
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background: rgba(99,102,241,.2);
  color: #818cf8;
  font-size: 10px;
  font-weight: 800;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  margin-top: 1px;
}

/* ─────────────────────────── DARK FEED LIVE ─────────────────────────────── */
.v2-df-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 0 14px;
  flex-wrap: wrap;
  flex-shrink: 0;
}
.v2-df-status {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 12px;
  color: #64748b;
}
.v2-df-status-text { font-weight: 600; }
.v2-df-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
  overflow-y: auto;
  max-height: calc(100vh - 280px);
  scrollbar-width: thin;
  scrollbar-color: #1e293b transparent;
}
.v2-df-list::-webkit-scrollbar { width: 4px; }
.v2-df-list::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }
.v2-df-entry {
  background: rgba(10,22,40,.7);
  border: 1px solid rgba(255,255,255,.06);
  border-radius: 10px;
  padding: 12px 14px;
  transition: all .15s;
}
.v2-df-entry:hover {
  background: rgba(15,30,55,.85);
  border-color: rgba(255,255,255,.1);
}
.v2-df-entry-header {
  display: flex;
  align-items: center;
  gap: 7px;
  flex-wrap: wrap;
  margin-bottom: 6px;
}
.v2-df-sev {
  font-size: 10px;
  font-weight: 800;
  padding: 2px 7px;
  border-radius: 4px;
  flex-shrink: 0;
}
.v2-df-actor {
  font-size: 12px;
  font-weight: 700;
  color: #f1f5f9;
}
.v2-df-source {
  font-size: 10px;
  color: #475569;
  display: flex;
  align-items: center;
  gap: 4px;
}
.v2-df-time {
  font-size: 10px;
  color: #334155;
  margin-left: auto;
}
.v2-df-summary {
  font-size: 12px;
  color: #94a3b8;
  line-height: 1.6;
  margin-bottom: 6px;
}
.v2-df-iocs {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-bottom: 8px;
}
.v2-df-actions {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

/* ─────────────────────────── PREDICTIVE INTEL ───────────────────────────── */
.v2-pred-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 14px;
}
.v2-pred-card {
  background: rgba(10,22,40,.7);
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 12px;
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.v2-pred-card-title {
  font-size: 12px;
  font-weight: 700;
  color: #f1f5f9;
  display: flex;
  align-items: center;
  gap: 7px;
  padding-bottom: 8px;
  border-bottom: 1px solid rgba(255,255,255,.06);
}
.v2-pred-score-card {
  align-items: center;
  text-align: center;
}
.v2-pred-score-title {
  font-size: 13px;
  font-weight: 700;
  color: #94a3b8;
  letter-spacing: .04em;
}
.v2-pred-gauge-wrap {
  display: flex;
  justify-content: center;
}
.v2-pred-score-val {
  font-size: 44px;
  font-weight: 900;
  color: #f97316;
  line-height: 1;
  letter-spacing: -.04em;
}
#v2-pred-score-num { animation: v2countUp .6s ease both; }
.v2-pred-score-sub {
  font-size: 11px;
  color: #64748b;
  margin-top: 4px;
}
.v2-pred-emerging-card { }

/* Geo heat list */
.v2-geo-list { display: flex; flex-direction: column; gap: 6px; }
.v2-geo-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.v2-geo-label {
  font-size: 11px;
  color: #94a3b8;
  min-width: 100px;
}
.v2-geo-bar-wrap {
  flex: 1;
  height: 5px;
  background: rgba(255,255,255,.06);
  border-radius: 3px;
  overflow: hidden;
}
.v2-geo-bar {
  height: 100%;
  border-radius: 3px;
  transition: width .5s ease;
}
.v2-geo-score {
  font-size: 11px;
  font-weight: 700;
  min-width: 24px;
  text-align: right;
}
.v2-geo-type {
  font-size: 9px;
  color: #475569;
  min-width: 90px;
  text-align: right;
}

/* Emerging threat list */
.v2-emerging-list { display: flex; flex-direction: column; gap: 6px; }
.v2-emerging-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 0;
  border-bottom: 1px solid rgba(255,255,255,.04);
}
.v2-emerging-item:last-child { border-bottom: none; }
.v2-emerging-name { flex: 1; font-size: 12px; color: #cbd5e1; }
.v2-emerging-conf { font-size: 11px; font-weight: 700; }

/* ─────────────────────────── DECEPTION DETECT ───────────────────────────── */
.v2-deception-layout {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  min-height: 480px;
}
.v2-deception-input-panel {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.v2-deception-title {
  font-size: 16px;
  font-weight: 800;
  color: #f1f5f9;
  display: flex;
  align-items: center;
  gap: 8px;
}
.v2-deception-subtitle {
  font-size: 12px;
  color: #64748b;
  line-height: 1.6;
}
.v2-deception-samples {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.v2-deception-textarea {
  flex: 1;
  min-height: 200px;
  background: #060f1e;
  border: 1px solid rgba(255,255,255,.1);
  border-radius: 10px;
  color: #e2e8f0;
  font-family: 'JetBrains Mono', Consolas, monospace;
  font-size: 11px;
  line-height: 1.7;
  padding: 12px;
  outline: none;
  resize: vertical;
  transition: border-color .2s;
}
.v2-deception-textarea:focus {
  border-color: rgba(239,68,68,.4);
  box-shadow: 0 0 0 3px rgba(239,68,68,.07);
}
.v2-deception-textarea::placeholder { color: #334155; }
.v2-deception-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.v2-deception-results-panel {
  background: rgba(10,22,40,.6);
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 12px;
  padding: 16px;
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: #1e293b transparent;
}
.v2-deception-results-panel::-webkit-scrollbar { width: 4px; }
.v2-deception-results-panel::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }
.v2-deception-placeholder {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  min-height: 200px;
  text-align: center;
  color: #334155;
  font-size: 12px;
  line-height: 1.8;
}
.v2-deception-result { animation: v2popIn .35s ease both; }
.v2-dr-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding-bottom: 12px;
  border-bottom: 1px solid rgba(255,255,255,.06);
  margin-bottom: 14px;
}
.v2-dr-verdict {
  font-size: 14px;
  font-weight: 800;
  letter-spacing: .04em;
  text-transform: uppercase;
  padding: 5px 14px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  gap: 7px;
}
.v2-dr-confidence {
  font-size: 22px;
  font-weight: 800;
  color: #ef4444;
}
.v2-dr-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
  margin-bottom: 14px;
}
.v2-dr-item {
  display: flex;
  flex-direction: column;
  gap: 3px;
  padding: 8px 10px;
  background: rgba(255,255,255,.02);
  border: 1px solid rgba(255,255,255,.05);
  border-radius: 7px;
}
.v2-dr-lbl {
  font-size: 9px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: #475569;
}
.v2-dr-val { font-size: 12px; color: #e2e8f0; font-weight: 600; }
.v2-dr-section { margin-bottom: 12px; }
.v2-dr-section h4 {
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: #475569;
  margin: 0 0 7px;
}
.v2-dr-indicator {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 12px;
  color: #94a3b8;
  padding: 4px 0;
}
.v2-dr-actions { display: flex; gap: 8px; flex-wrap: wrap; }

/* ─────────────────────────── EXEC REPORTS ───────────────────────────────── */
.v2-report-layout {
  display: grid;
  grid-template-columns: 300px 1fr;
  gap: 20px;
  min-height: 500px;
}
.v2-report-builder {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.v2-report-title {
  font-size: 15px;
  font-weight: 800;
  color: #f1f5f9;
  display: flex;
  align-items: center;
  gap: 8px;
  padding-bottom: 10px;
  border-bottom: 1px solid rgba(255,255,255,.06);
}
.v2-rtype-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 7px;
}
.v2-rtype-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: 4px;
  padding: 10px 8px;
  background: rgba(255,255,255,.03);
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 9px;
  cursor: pointer;
  transition: all .15s;
}
.v2-rtype-card:hover {
  background: rgba(255,255,255,.06);
  border-color: rgba(99,102,241,.3);
}
.v2-rtype-card.active {
  background: rgba(99,102,241,.12);
  border-color: rgba(99,102,241,.5);
}
.v2-rtype-label {
  font-size: 10px;
  font-weight: 700;
  color: #cbd5e1;
  line-height: 1.3;
}
.v2-rtype-desc { font-size: 9px; color: #475569; }

.v2-report-opts { display: flex; flex-direction: column; gap: 8px; }
.v2-report-opt-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.v2-opt-lbl {
  font-size: 11px;
  font-weight: 600;
  color: #64748b;
}
.v2-report-sections { }
.v2-report-sections h4 {
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: #475569;
  margin: 0 0 8px;
}
.v2-section-item {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 11px;
  color: #94a3b8;
  padding: 4px 0;
  cursor: pointer;
  transition: color .15s;
}
.v2-section-item:hover { color: #f1f5f9; }
.v2-section-item input[type="checkbox"] {
  width: 13px;
  height: 13px;
  accent-color: #6366f1;
  cursor: pointer;
}
.v2-report-actions { display: flex; flex-wrap: wrap; gap: 6px; }

/* Report preview */
.v2-report-preview {
  background: rgba(10,22,40,.6);
  border: 1px solid rgba(255,255,255,.07);
  border-radius: 12px;
  overflow-y: auto;
  padding: 20px;
  scrollbar-width: thin;
  scrollbar-color: #1e293b transparent;
}
.v2-report-preview::-webkit-scrollbar { width: 4px; }
.v2-report-preview::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }
.v2-report-placeholder {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  min-height: 300px;
  text-align: center;
  color: #334155;
  font-size: 12px;
  line-height: 1.8;
}
.v2-report-doc { animation: v2fadeIn .3s ease both; }
.v2-report-doc-header {
  padding-bottom: 14px;
  border-bottom: 2px solid rgba(255,255,255,.08);
  margin-bottom: 18px;
}
.v2-report-doc-title {
  font-size: 17px;
  font-weight: 800;
  color: #f1f5f9;
}
.v2-report-section {
  margin-bottom: 20px;
  padding-bottom: 20px;
  border-bottom: 1px solid rgba(255,255,255,.05);
}
.v2-report-section:last-child { border-bottom: none; }
.v2-report-section h2 {
  font-size: 13px;
  font-weight: 800;
  color: #f1f5f9;
  margin: 0 0 12px;
  display: flex;
  align-items: center;
  gap: 8px;
  text-transform: uppercase;
  letter-spacing: .05em;
}
.v2-report-section p {
  font-size: 12px;
  color: #94a3b8;
  line-height: 1.8;
  margin: 0 0 10px;
}
.v2-report-kpi-row {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: 12px;
}
.v2-report-kpi {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 10px 20px;
  background: rgba(255,255,255,.03);
  border: 1px solid rgba(255,255,255,.06);
  border-radius: 8px;
  min-width: 80px;
  text-align: center;
}
.v2-report-kpi-val {
  font-size: 24px;
  font-weight: 900;
  line-height: 1;
}
.v2-report-kpi-lbl {
  font-size: 9px;
  color: #475569;
  text-transform: uppercase;
  letter-spacing: .06em;
  margin-top: 3px;
}
.v2-report-campaign-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  background: rgba(255,255,255,.02);
  border: 1px solid rgba(255,255,255,.05);
  border-radius: 7px;
  margin-bottom: 6px;
  font-size: 12px;
  color: #94a3b8;
  flex-wrap: wrap;
}
.v2-report-actor-row {
  padding: 8px 0;
  font-size: 12px;
  color: #94a3b8;
  line-height: 1.7;
}
.v2-report-rec {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 7px 0;
  border-bottom: 1px solid rgba(255,255,255,.04);
  font-size: 12px;
  color: #94a3b8;
  line-height: 1.5;
}
.v2-report-rec:last-child { border-bottom: none; }

/* ─────────────────────────── HEATMAP ────────────────────────────────────── */
.v2-heatmap-wrap {
  width: 100%;
  overflow-x: auto;
}
.v2-heatmap-header {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 8px;
  flex-wrap: wrap;
}
.v2-heatmap-tooltip {
  z-index: 9999 !important;
  pointer-events: none !important;
}

/* ─────────────────────────── STALE / WARN ───────────────────────────────── */
.v2-stale-warn {
  display: none;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  color: #f97316;
  padding: 2px 8px;
  border-radius: 4px;
  background: rgba(249,115,22,.12);
}

/* ─────────────────────────── RESPONSIVE ─────────────────────────────────── */
@media (max-width: 900px) {
  .v2-actor-layout,
  .v2-kc-layout { grid-template-columns: 1fr; }
  .v2-actor-roster,
  .v2-kc-nav {
    border-right: none;
    border-bottom: 1px solid rgba(255,255,255,.07);
    max-height: 180px;
  }
  .v2-actor-list { flex-direction: row; flex-wrap: wrap; gap: 4px; }
  .v2-actor-row { min-width: 160px; }
  .v2-nc-layout { grid-template-columns: 1fr; }
  .v2-nc-detail-panel { min-height: 200px; }
  .v2-deception-layout { grid-template-columns: 1fr; }
  .v2-report-layout { grid-template-columns: 1fr; }
  .v2-report-builder { order: 2; }
  .v2-report-preview { order: 1; min-height: 280px; }
  .v2-engine { padding: 14px 14px; }
  .v2-header { padding: 10px 14px; }
  .v2-pred-grid { grid-template-columns: 1fr; }
}
@media (max-width: 600px) {
  .v2-header-right { display: none; }
  .v2-header-title { font-size: 11px; }
  .v2-tab { padding: 8px 10px; font-size: 10px; }
  .v2-rtype-grid { grid-template-columns: 1fr; }
  .v2-kpi-item { min-width: 85px; padding: 8px 14px; }
  .v2-kpi-val { font-size: 15px; }
  .v2-kc-chain { flex-direction: column; }
  .v2-stage-arrow { transform: rotate(90deg); }
}
"""

with open('/home/user/webapp/css/darkweb-cdwie-v2.css', 'w') as f:
    f.write(css)

lines = css.count('\n') + 1
size  = len(css.encode('utf-8'))
print(f"Written: {lines} lines ({size:,} bytes)")
