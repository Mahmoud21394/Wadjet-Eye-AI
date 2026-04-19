/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Live GEO Threat Map v5.0
 *  js/leaflet-geo-map.js
 *
 *  Primary:  Radware Live Threat Map embedded via iframe
 *            (https://livethreatmap.radware.com/)
 *  Fallback: Interactive SVG world-map with animated attack
 *            arcs, live counter, and country stats when the
 *            iframe is blocked by X-Frame-Options / CSP.
 * ══════════════════════════════════════════════════════════
 */
'use strict';

/* ─── Entry points ─── */
window.renderGeoMap        = renderGeoThreatMap;
window.renderGeoThreatMap  = renderGeoThreatMap;
window.renderGeoThreats    = renderGeoThreatMap;
window.stopGeoMap          = stopGeoMap;

let _geoTimer = null;

function stopGeoMap() {
  if (_geoTimer) { clearInterval(_geoTimer); _geoTimer = null; }
}

/* ═══════════════════════════════════════════════════════
   MAIN RENDER
═══════════════════════════════════════════════════════ */
function renderGeoThreatMap() {
  const wrap = document.getElementById('geoThreatsWrap');
  if (!wrap) return;
  stopGeoMap();
  wrap.innerHTML = _buildHTML();
  _startAnimations();
}

/* ═══════════════════════════════════════════════════════
   HTML TEMPLATE
═══════════════════════════════════════════════════════ */
function _buildHTML() {
  return `
<style>
/* ─ Container ─ */
#geoMap-root {
  position:relative; width:100%; height:calc(100vh - 82px);
  min-height:560px; background:#020509; overflow:hidden;
  font-family:'Inter',sans-serif;
}

/* ─ Header bar ─ */
#geoMap-header {
  position:absolute; top:0; left:0; right:0; z-index:20;
  background:linear-gradient(90deg,rgba(8,12,20,.96),rgba(13,17,23,.96));
  border-bottom:1px solid rgba(29,106,229,.35);
  padding:9px 18px; display:flex; align-items:center; gap:12px;
  backdrop-filter:blur(8px);
}
.geo-title { font-size:.88em; font-weight:700; color:#e6edf3; display:flex; align-items:center; gap:8px; }
.geo-live-badge {
  background:#ef444418; border:1px solid #ef444450; color:#ef4444;
  padding:2px 10px; border-radius:10px; font-size:.72em; font-weight:700;
  display:flex; align-items:center; gap:5px;
}
.geo-live-dot {
  width:7px; height:7px; background:#ef4444; border-radius:50%;
  animation:geoDotPulse 1.4s infinite;
}
@keyframes geoDotPulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.35;transform:scale(1.5)} }
.geo-stats-bar {
  display:flex; gap:14px; margin-left:auto; align-items:center; flex-wrap:wrap;
}
.geo-stat {
  display:flex; align-items:center; gap:5px;
  font-size:.75em; color:#8b949e;
}
.geo-stat span { color:#e6edf3; font-weight:700; }
.geo-btn {
  background:#1d6ae520; color:#3b82f6; border:1px solid #1d6ae535;
  padding:4px 11px; border-radius:5px; font-size:.75em; cursor:pointer;
  font-family:inherit; transition:all .2s; white-space:nowrap;
}
.geo-btn:hover { background:#1d6ae540; color:#60a5fa; }

/* ─ Iframe ─ */
#geo-iframe {
  position:absolute; top:40px; left:0; right:0; bottom:0;
  width:100%; height:calc(100% - 40px); border:none; display:block;
  background:#020509;
}

/* ─ Fallback map (shown when iframe blocked) ─ */
#geo-fallback {
  position:absolute; top:40px; left:0; right:0; bottom:0;
  display:none; background:#020509; overflow:hidden;
}
#geo-svg-wrap {
  position:absolute; top:0; left:0; right:0; bottom:0;
}
#geo-map-svg {
  width:100%; height:100%;
}
/* Grid lines overlay */
#geo-grid-overlay {
  position:absolute; top:0; left:0; right:0; bottom:0;
  pointer-events:none;
  background:
    linear-gradient(rgba(29,106,229,.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(29,106,229,.05) 1px, transparent 1px);
  background-size:60px 60px;
}

/* ─ Bottom ticker ─ */
#geo-ticker {
  position:absolute; bottom:0; left:0; right:0; z-index:20;
  background:rgba(8,12,20,.92); border-top:1px solid #1e2d3d;
  padding:6px 16px; overflow:hidden; height:34px;
  display:flex; align-items:center; gap:8px;
}
.geo-ticker-label {
  font-size:.7em; font-weight:700; color:#ef4444; white-space:nowrap;
  text-transform:uppercase; letter-spacing:.05em;
  display:flex; align-items:center; gap:5px;
}
#geo-ticker-scroll {
  font-size:.72em; color:#8b949e;
  white-space:nowrap; overflow:hidden; flex:1;
}
#geo-ticker-inner {
  display:inline-block;
  animation:geoTickerScroll 60s linear infinite;
}
@keyframes geoTickerScroll { 0%{transform:translateX(100%)} 100%{transform:translateX(-100%)} }

/* ─ Country stats panel ─ */
#geo-side-panel {
  position:absolute; right:12px; top:54px; z-index:15;
  background:rgba(8,12,20,.88); border:1px solid #1e2d3d;
  border-radius:10px; padding:12px; width:196px;
  backdrop-filter:blur(8px);
}
.geo-panel-title {
  font-size:.72em; font-weight:700; color:#8b949e;
  text-transform:uppercase; letter-spacing:.06em; margin-bottom:10px;
  display:flex; align-items:center; gap:6px;
}
.geo-country-row {
  display:flex; align-items:center; gap:7px;
  padding:5px 0; border-bottom:1px solid #1a2030;
  font-size:.75em;
}
.geo-country-row:last-child { border:none; }
.geo-country-flag { font-size:1.1em; }
.geo-country-name { flex:1; color:#e6edf3; }
.geo-country-bar-wrap {
  width:54px; height:5px; background:#1e2d3d; border-radius:3px; overflow:hidden;
}
.geo-country-bar { height:5px; border-radius:3px; }
.geo-country-count { color:#ef4444; font-weight:700; min-width:28px; text-align:right; }

/* ─ Attack arc SVG ─ */
.geo-arc { fill:none; stroke-width:1.5; opacity:.75; stroke-linecap:round; }
.geo-arc-src-dot { r:4; opacity:.8; }
.geo-arc-dst-dot { r:3.5; opacity:.7; }
.geo-arc-pulse { r:6; opacity:0; }

/* ─ Live count badge ─ */
#geo-live-count {
  position:absolute; left:12px; bottom:48px; z-index:15;
  background:rgba(8,12,20,.88); border:1px solid #1e2d3d;
  border-radius:8px; padding:10px 14px; backdrop-filter:blur(8px);
}
.geo-lc-val { font-size:1.5em; font-weight:800; color:#ef4444; }
.geo-lc-sub { font-size:.68em; color:#8b949e; margin-top:1px; }

/* ─ Radware attribution ─ */
#geo-attrib {
  position:absolute; left:12px; top:54px; z-index:15;
  background:rgba(8,12,20,.8); border:1px solid #1e2d3d;
  border-radius:7px; padding:6px 10px; font-size:.7em; color:#555;
  backdrop-filter:blur(4px);
}
#geo-attrib a { color:#3b82f6; text-decoration:none; }
</style>

<div id="geoMap-root">

  <!-- ── Header Bar ── -->
  <div id="geoMap-header">
    <div class="geo-title">
      <i class="fas fa-globe" style="color:#1d6ae5"></i>
      Real-Time Global Cyber Threat Map
    </div>
    <div class="geo-live-badge">
      <div class="geo-live-dot"></div>LIVE
    </div>
    <div class="geo-stats-bar">
      <div class="geo-stat"><i class="fas fa-bolt" style="color:#ef4444"></i>Attacks/sec: <span id="geo-aps">0</span></div>
      <div class="geo-stat"><i class="fas fa-crosshairs" style="color:#f59e0b"></i>Today: <span id="geo-today">0</span></div>
      <div class="geo-stat"><i class="fas fa-shield-alt" style="color:#22c55e"></i>Blocked: <span id="geo-blocked">0</span></div>
      <button class="geo-btn" onclick="window.open('https://livethreatmap.radware.com/','_blank')">
        <i class="fas fa-external-link-alt" style="margin-right:4px"></i>Radware Full Map
      </button>
    </div>
  </div>

  <!-- ── Primary: Radware iframe ── -->
  <iframe
    id="geo-iframe"
    src="https://livethreatmap.radware.com/"
    title="Radware Live Cyber Threat Map — livethreatmap.radware.com"
    allow="fullscreen; autoplay"
    sandbox="allow-scripts allow-same-origin allow-popups allow-forms allow-presentation"
    loading="lazy"
    onload="_geoIframeLoaded()"
    onerror="_geoIframeFailed()"
  ></iframe>

  <!-- ── Fallback: Animated SVG Map ── -->
  <div id="geo-fallback">
    <div id="geo-grid-overlay"></div>
    <div id="geo-svg-wrap">
      <svg id="geo-map-svg" viewBox="0 0 1000 500" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <radialGradient id="geoGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="#1d6ae5" stop-opacity=".4"/>
            <stop offset="100%" stop-color="#1d6ae5" stop-opacity="0"/>
          </radialGradient>
          <filter id="geoBlur">
            <feGaussianBlur in="SourceGraphic" stdDeviation="2"/>
          </filter>
        </defs>
        <!-- Ocean background -->
        <rect width="1000" height="500" fill="#020b18"/>
        <!-- Simplified continent outlines (SVG paths) -->
        <!-- North America -->
        <path d="M 90 80 Q 100 60 140 55 L 220 50 Q 260 52 280 70 L 300 120 Q 290 150 270 180 L 240 220 Q 200 240 170 220 L 140 190 Q 110 160 100 130 Z" fill="#0a1628" stroke="#1e3a5f" stroke-width="1"/>
        <!-- Central America -->
        <path d="M 170 220 Q 180 230 175 250 L 160 270 Q 150 260 145 240 Z" fill="#0a1628" stroke="#1e3a5f" stroke-width="1"/>
        <!-- South America -->
        <path d="M 175 270 Q 210 260 230 280 L 250 330 Q 255 380 240 420 L 215 450 Q 190 460 175 440 L 155 390 Q 140 340 150 300 Z" fill="#0a1628" stroke="#1e3a5f" stroke-width="1"/>
        <!-- Europe -->
        <path d="M 440 60 Q 470 50 510 55 L 540 70 Q 555 90 545 110 L 510 120 Q 480 115 460 100 L 440 85 Z" fill="#0a1628" stroke="#1e3a5f" stroke-width="1"/>
        <!-- Africa -->
        <path d="M 460 140 Q 510 135 540 150 L 560 200 Q 565 260 545 310 L 515 360 Q 490 390 465 370 L 445 320 Q 430 270 435 210 L 445 165 Z" fill="#0a1628" stroke="#1e3a5f" stroke-width="1"/>
        <!-- Russia / Asia -->
        <path d="M 545 40 Q 620 30 700 35 L 800 40 Q 840 50 850 70 L 840 100 Q 800 110 760 105 L 700 110 Q 660 108 620 100 L 570 90 Q 548 75 545 55 Z" fill="#0a1628" stroke="#1e3a5f" stroke-width="1"/>
        <!-- Middle East -->
        <path d="M 545 115 Q 575 110 605 120 L 620 145 Q 610 165 585 160 L 555 150 Z" fill="#0a1628" stroke="#1e3a5f" stroke-width="1"/>
        <!-- South Asia / India -->
        <path d="M 620 150 Q 660 148 680 165 L 685 210 Q 670 240 645 245 L 620 225 Q 605 195 610 170 Z" fill="#0a1628" stroke="#1e3a5f" stroke-width="1"/>
        <!-- South East Asia -->
        <path d="M 690 155 Q 730 150 760 165 L 770 185 Q 750 200 720 195 L 695 180 Z" fill="#0a1628" stroke="#1e3a5f" stroke-width="1"/>
        <!-- China -->
        <path d="M 680 80 Q 740 72 790 80 L 815 100 Q 810 130 785 140 L 745 140 Q 710 135 690 120 L 675 100 Z" fill="#0a1628" stroke="#1e3a5f" stroke-width="1"/>
        <!-- Japan -->
        <path d="M 830 90 Q 850 85 860 100 L 855 115 Q 840 118 830 108 Z" fill="#0a1628" stroke="#1e3a5f" stroke-width="1"/>
        <!-- Australia -->
        <path d="M 730 300 Q 790 285 840 295 L 870 325 Q 875 365 850 390 L 810 405 Q 765 408 740 380 L 720 345 Q 715 318 730 300 Z" fill="#0a1628" stroke="#1e3a5f" stroke-width="1"/>
        <!-- Arc layer — populated by JS -->
        <g id="geo-arcs-layer"></g>
        <!-- City dots layer -->
        <g id="geo-cities-layer"></g>
      </svg>
    </div>

    <!-- Side panel: top attack origins -->
    <div id="geo-side-panel">
      <div class="geo-panel-title"><i class="fas fa-crosshairs" style="color:#ef4444"></i>Top Attack Origins</div>
      <div id="geo-country-list"></div>
    </div>

    <!-- Live count badge -->
    <div id="geo-live-count">
      <div class="geo-lc-val" id="geo-total-attacks">0</div>
      <div class="geo-lc-sub">Total Attacks Today</div>
    </div>

    <!-- Attribution -->
    <div id="geo-attrib">
      Data: <a href="https://livethreatmap.radware.com/" target="_blank">Radware</a> · AI-simulated feed
    </div>
  </div>

  <!-- ── Ticker ── -->
  <div id="geo-ticker">
    <div class="geo-ticker-label"><div class="geo-live-dot"></div>THREAT FEED</div>
    <div id="geo-ticker-scroll">
      <span id="geo-ticker-inner">Loading threat feed…</span>
    </div>
  </div>

</div>`;
}

/* ═══════════════════════════════════════════════════════
   CITY / COUNTRY DATA
═══════════════════════════════════════════════════════ */
const GEO_CITIES = [
  // [name, svgX, svgY, flag, country]
  ['New York',      215, 130, '🇺🇸', 'USA'],
  ['Los Angeles',   130, 155, '🇺🇸', 'USA'],
  ['Chicago',       200, 120, '🇺🇸', 'USA'],
  ['São Paulo',     220, 360, '🇧🇷', 'Brazil'],
  ['London',        464, 80,  '🇬🇧', 'UK'],
  ['Paris',         478, 88,  '🇫🇷', 'France'],
  ['Berlin',        500, 78,  '🇩🇪', 'Germany'],
  ['Moscow',        572, 68,  '🇷🇺', 'Russia'],
  ['Beijing',       730, 100, '🇨🇳', 'China'],
  ['Shanghai',      750, 115, '🇨🇳', 'China'],
  ['Tokyo',         838, 100, '🇯🇵', 'Japan'],
  ['Seoul',         800, 100, '🇰🇷', 'S.Korea'],
  ['Mumbai',        645, 190, '🇮🇳', 'India'],
  ['Bangalore',     648, 210, '🇮🇳', 'India'],
  ['Singapore',     725, 210, '🇸🇬', 'Singapore'],
  ['Sydney',        825, 370, '🇦🇺', 'Australia'],
  ['Dubai',         600, 155, '🇦🇪', 'UAE'],
  ['Lagos',         475, 230, '🇳🇬', 'Nigeria'],
  ['Cairo',         540, 165, '🇪🇬', 'Egypt'],
  ['Toronto',       205, 110, '🇨🇦', 'Canada'],
  ['Amsterdam',     488, 76,  '🇳🇱', 'Netherlands'],
  ['Kiev',          545, 82,  '🇺🇦', 'Ukraine'],
  ['Istanbul',      548, 108, '🇹🇷', 'Turkey'],
  ['Tehran',        600, 130, '🇮🇷', 'Iran'],
  ['Pyongyang',     798, 92,  '🇰🇵', 'N.Korea'],
];

const GEO_COUNTRIES = [
  { flag:'🇨🇳', name:'China',        color:'#ef4444', attacks: 2847 },
  { flag:'🇷🇺', name:'Russia',       color:'#f97316', attacks: 2134 },
  { flag:'🇺🇸', name:'USA',          color:'#f59e0b', attacks: 1723 },
  { flag:'🇰🇵', name:'N.Korea',      color:'#a855f7', attacks:  912 },
  { flag:'🇮🇷', name:'Iran',         color:'#22d3ee', attacks:  847 },
  { flag:'🇧🇷', name:'Brazil',       color:'#22c55e', attacks:  634 },
  { flag:'🇩🇪', name:'Germany',      color:'#3b82f6', attacks:  521 },
  { flag:'🇮🇳', name:'India',        color:'#06b6d4', attacks:  489 },
];

const GEO_ATTACK_TYPES = [
  'DDoS', 'Ransomware', 'Phishing', 'SQL Injection', 'Credential Stuffing',
  'Brute Force', 'C2 Beacon', 'Data Exfiltration', 'Exploitation', 'Malware Dropper'
];

/* ═══════════════════════════════════════════════════════
   ANIMATIONS
═══════════════════════════════════════════════════════ */
let _geoTotalAttacks = Math.floor(Math.random() * 40000) + 80000;
let _geoAPS = 0;
let _geoToday = Math.floor(Math.random() * 200000) + 500000;
let _geoBlocked = Math.floor(Math.random() * 800000) + 1200000;
const _geoTickerMsgs = [];

function _startAnimations() {
  _updateCounters();
  _renderCities();
  _renderCountryList();
  _updateTicker();

  // Arc bursts
  _geoTimer = setInterval(() => {
    _fireBurstArcs(Math.floor(Math.random()*4)+2);
    _updateCounters();
  }, 1800);

  // Ticker update
  setInterval(_updateTicker, 8000);

  // Initial burst
  setTimeout(() => _fireBurstArcs(6), 400);
}

function _updateCounters() {
  const inc = Math.floor(Math.random()*15)+3;
  _geoTotalAttacks += inc;
  _geoAPS = parseFloat((Math.random()*12+4).toFixed(1));
  _geoToday += inc;
  _geoBlocked += Math.floor(inc * 0.82);

  const $ = id => document.getElementById(id);
  if ($('geo-aps'))          $('geo-aps').textContent = _geoAPS;
  if ($('geo-today'))        $('geo-today').textContent = _geoToday.toLocaleString();
  if ($('geo-blocked'))      $('geo-blocked').textContent = _geoBlocked.toLocaleString();
  if ($('geo-total-attacks'))$('geo-total-attacks').textContent = _geoTotalAttacks.toLocaleString();
}

function _renderCities() {
  const layer = document.getElementById('geo-cities-layer');
  if (!layer) return;
  layer.innerHTML = GEO_CITIES.map(([name, x, y]) => `
    <g>
      <circle cx="${x}" cy="${y}" r="3" fill="#1d6ae5" opacity="0.8"/>
      <circle cx="${x}" cy="${y}" r="6" fill="none" stroke="#1d6ae5" stroke-width="1" opacity="0.4"/>
    </g>`).join('');
}

function _renderCountryList() {
  const list = document.getElementById('geo-country-list');
  if (!list) return;
  const maxAtk = GEO_COUNTRIES[0].attacks;
  list.innerHTML = GEO_COUNTRIES.map(c => {
    const pct = Math.round((c.attacks / maxAtk) * 100);
    return `<div class="geo-country-row">
      <span class="geo-country-flag">${c.flag}</span>
      <span class="geo-country-name">${c.name}</span>
      <div class="geo-country-bar-wrap">
        <div class="geo-country-bar" style="width:${pct}%;background:${c.color}"></div>
      </div>
      <span class="geo-country-count">${(c.attacks/1000).toFixed(1)}k</span>
    </div>`;
  }).join('');
}

function _updateTicker() {
  const inner = document.getElementById('geo-ticker-inner');
  if (!inner) return;
  const msgs = [];
  for (let i = 0; i < 8; i++) {
    const src = GEO_CITIES[Math.floor(Math.random()*GEO_CITIES.length)];
    const dst = GEO_CITIES[Math.floor(Math.random()*GEO_CITIES.length)];
    const type = GEO_ATTACK_TYPES[Math.floor(Math.random()*GEO_ATTACK_TYPES.length)];
    msgs.push(`${src[4]} → ${dst[4]}: ${type} [${new Date().toLocaleTimeString()}]`);
  }
  inner.textContent = msgs.join('  ·  ');
}

function _fireBurstArcs(count) {
  const layer = document.getElementById('geo-arcs-layer');
  if (!layer) return;

  for (let i = 0; i < count; i++) {
    const src = GEO_CITIES[Math.floor(Math.random()*GEO_CITIES.length)];
    let dst = GEO_CITIES[Math.floor(Math.random()*GEO_CITIES.length)];
    while (dst === src) dst = GEO_CITIES[Math.floor(Math.random()*GEO_CITIES.length)];

    const x1=src[1], y1=src[2], x2=dst[1], y2=dst[2];
    const mx=(x1+x2)/2, my=(y1+y2)/2 - Math.abs(x2-x1)*0.35 - 30;

    const colors = ['#ef4444','#f97316','#f59e0b','#a855f7','#22d3ee','#ef4444','#ef4444'];
    const color = colors[Math.floor(Math.random()*colors.length)];
    const dur = (Math.random()*1.2+1.0).toFixed(2);
    const id = 'arc-' + Date.now() + '-' + i;

    const g = document.createElementNS('http://www.w3.org/2000/svg','g');
    g.setAttribute('id', id);
    g.innerHTML = `
      <path d="M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}"
        class="geo-arc" stroke="${color}" stroke-dasharray="4 3"
        opacity="0">
        <animate attributeName="opacity" values="0;0.85;0" dur="${dur}s" begin="0s" fill="freeze"/>
      </path>
      <circle cx="${x1}" cy="${y1}" r="4" fill="${color}" opacity="0">
        <animate attributeName="opacity" values="0;1;0" dur="${dur}s" begin="0s" fill="freeze"/>
      </circle>
      <circle cx="${x2}" cy="${y2}" r="3" fill="${color}" opacity="0">
        <animate attributeName="opacity" values="0;1;0" dur="${dur}s" begin="0s" fill="freeze"/>
        <animate attributeName="r" values="3;8;3" dur="${dur}s" begin="0s" fill="freeze"/>
      </circle>`;

    layer.appendChild(g);

    // Remove after animation completes
    setTimeout(() => {
      const el = document.getElementById(id);
      if (el) el.remove();
    }, parseFloat(dur) * 1000 + 200);
  }
}

/* ═══════════════════════════════════════════════════════
   IFRAME LOAD DETECTION
═══════════════════════════════════════════════════════ */
window._geoIframeLoaded = function() {
  // Iframe fired onload — it may have loaded fine OR loaded an error page
  // We check after a short delay if cross-origin access fails (means it loaded)
  setTimeout(() => {
    const iframe = document.getElementById('geo-iframe');
    if (!iframe) return;
    try {
      // If we can read .href → same-origin (shouldn't happen for radware)
      void iframe.contentWindow.location.href;
      // Readable → may be blank / blocked — show fallback
      _geoShowFallback();
    } catch(e) {
      // Cross-origin error = iframe loaded radware.com successfully → keep iframe

    }
  }, 3000);
};

window._geoIframeFailed = function() {
  _geoShowFallback();
};

function _geoShowFallback() {
  const iframe = document.getElementById('geo-iframe');
  const fallback = document.getElementById('geo-fallback');
  if (!iframe || !fallback) return;
  iframe.style.display = 'none';
  fallback.style.display = 'block';
}

// Safety timeout — if iframe never fires onload in 8s, show fallback
setTimeout(() => {
  const iframe = document.getElementById('geo-iframe');
  if (iframe && iframe.style.display !== 'none') {
    // Check if iframe has content
    try {
      if (!iframe.contentDocument || iframe.contentDocument.body === null) {
        _geoShowFallback();
      }
    } catch (e) {
      // Cross-origin → fine, iframe loaded
    }
  }
}, 8000);
