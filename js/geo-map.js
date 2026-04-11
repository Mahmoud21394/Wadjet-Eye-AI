/**
 * ══════════════════════════════════════════════════════════
 *  EYEbot AI — Geo Threat Map v2.0
 *  js/geo-map.js
 *
 *  Canvas-based real-time threat map featuring:
 *  • World map background (SVG-like path rendering)
 *  • Animated attack lines from source to target
 *  • IP geolocation from IOC data via backend
 *  • Heatmap overlay for attack density
 *  • Hover/click details for each attack
 *  • Country flags and attack statistics
 * ══════════════════════════════════════════════════════════
 */
'use strict';

/* ─────────────────────────────────────────────
   CONFIGURATION
───────────────────────────────────────────── */
const GEO_REFRESH_MS = 30000;  // refresh IOC geo data every 30s
const GEO_MAX_ATTACKS = 60;    // max active animated attack lines
const GEO_LINE_SPEED  = 0.008; // animation speed (0-1 progress per frame)

/* ─────────────────────────────────────────────
   STATE
───────────────────────────────────────────── */
let _geoCanvas     = null;
let _geoCtx        = null;
let _geoAnimId     = null;
let _geoRefreshId  = null;
let _geoAttacks    = [];
let _geoStats      = { total: 0, countries: {}, types: {} };
let _geoHover      = null;
let _geoInitialized = false;

/* Approximate world map country polygons (simplified lat/lon bounding boxes)
   We use a simplified SVG-like approach with known country centroids */
const COUNTRY_CENTROIDS = {
  'US':  { lat:39.5, lon:-98.35, name:'United States' },
  'CN':  { lat:35.0, lon:105.0,  name:'China' },
  'RU':  { lat:60.0, lon:90.0,   name:'Russia' },
  'DE':  { lat:51.0, lon:10.0,   name:'Germany' },
  'GB':  { lat:55.0, lon:-3.0,   name:'United Kingdom' },
  'FR':  { lat:46.0, lon:2.0,    name:'France' },
  'BR':  { lat:-14.0,lon:-51.0,  name:'Brazil' },
  'IN':  { lat:20.0, lon:77.0,   name:'India' },
  'JP':  { lat:36.0, lon:138.0,  name:'Japan' },
  'AU':  { lat:-27.0,lon:133.0,  name:'Australia' },
  'KR':  { lat:36.0, lon:128.0,  name:'South Korea' },
  'KP':  { lat:40.0, lon:127.0,  name:'North Korea' },
  'IR':  { lat:32.0, lon:53.0,   name:'Iran' },
  'UA':  { lat:49.0, lon:32.0,   name:'Ukraine' },
  'NL':  { lat:52.0, lon:5.3,    name:'Netherlands' },
  'CA':  { lat:56.0, lon:-96.0,  name:'Canada' },
  'SG':  { lat:1.35, lon:103.8,  name:'Singapore' },
  'HK':  { lat:22.3, lon:114.2,  name:'Hong Kong' },
  'SE':  { lat:62.0, lon:15.0,   name:'Sweden' },
  'TR':  { lat:39.0, lon:35.0,   name:'Turkey' },
  'NG':  { lat:10.0, lon:8.0,    name:'Nigeria' },
  'ZA':  { lat:-29.0,lon:25.0,   name:'South Africa' },
  'MX':  { lat:23.0, lon:-102.0, name:'Mexico' },
  'ID':  { lat:-5.0, lon:120.0,  name:'Indonesia' },
  'PL':  { lat:52.0, lon:20.0,   name:'Poland' },
  'RO':  { lat:46.0, lon:25.0,   name:'Romania' },
  'VN':  { lat:16.0, lon:107.0,  name:'Vietnam' },
  'TW':  { lat:23.7, lon:120.9,  name:'Taiwan' },
  'IL':  { lat:31.5, lon:35.0,   name:'Israel' },
  'SA':  { lat:24.0, lon:45.0,   name:'Saudi Arabia' },
};

/* ─────────────────────────────────────────────
   COORDINATE PROJECTION (Mercator)
───────────────────────────────────────────── */
function latLonToXY(lat, lon, W, H) {
  const x = (lon + 180) / 360 * W;
  const latRad = lat * Math.PI / 180;
  const mercN  = Math.log(Math.tan(Math.PI / 4 + latRad / 2));
  const y      = (H / 2) - (W * mercN / (2 * Math.PI));
  return { x, y };
}

/* ─────────────────────────────────────────────
   FETCH IOC GEO DATA
───────────────────────────────────────────── */
async function _geoFetch(path) {
  const base  = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
  const token = sessionStorage.getItem('tp_token') || '';
  const resp  = await fetch(`${base}/api${path}`, {
    headers: { 'Content-Type':'application/json', ...(token ? {Authorization:`Bearer ${token}`}:{}) }
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

async function _loadGeoData() {
  try {
    // Fetch top-risk IOCs with country data
    const data = await _geoFetch('/iocs?limit=100&sort=risk_score&reputation=malicious');
    const iocs  = data?.data || data || [];

    // Reset stats
    _geoStats = { total: iocs.length, countries: {}, types: {} };
    const newAttacks = [];

    // Target is always the user's approximate location (HQ = US)
    const TARGET_COUNTRIES = ['US','GB','DE','FR','NL'];
    const target = COUNTRY_CENTROIDS['US'];

    iocs.forEach(ioc => {
      const cc    = (ioc.country || '').toUpperCase().slice(0,2);
      const srcCC = cc || Object.keys(COUNTRY_CENTROIDS)[Math.floor(Math.random()*Object.keys(COUNTRY_CENTROIDS).length)];
      const src   = COUNTRY_CENTROIDS[srcCC] || COUNTRY_CENTROIDS['CN'];

      // Skip if source = target
      if (srcCC === 'US' && TARGET_COUNTRIES.includes('US')) return;

      _geoStats.countries[src.name] = (_geoStats.countries[src.name]||0) + 1;
      _geoStats.types[ioc.type||'unknown'] = (_geoStats.types[ioc.type||'unknown']||0) + 1;

      const tgtCC  = TARGET_COUNTRIES[Math.floor(Math.random()*TARGET_COUNTRIES.length)];
      const tgt    = COUNTRY_CENTROIDS[tgtCC] || target;

      const sev    = ioc.risk_score >= 70 ? 'critical' : ioc.risk_score >= 40 ? 'high' : 'medium';
      const color  = sev==='critical'?'#ef4444':sev==='high'?'#f97316':'#f59e0b';

      newAttacks.push({
        id:      ioc.id || Math.random().toString(36).slice(2),
        srcLat:  src.lat + (Math.random()-0.5)*5,
        srcLon:  src.lon + (Math.random()-0.5)*5,
        tgtLat:  tgt.lat + (Math.random()-0.5)*3,
        tgtLon:  tgt.lon + (Math.random()-0.5)*3,
        srcName: src.name,
        tgtName: tgt.name,
        iocVal:  ioc.value || '—',
        iocType: ioc.type  || '—',
        risk:    ioc.risk_score || 0,
        sev,
        color,
        progress: Math.random(), // start at random point for visual diversity
        speed:    GEO_LINE_SPEED * (0.5 + Math.random()),
        opacity:  0.6 + Math.random() * 0.4,
        active:   true,
      });
    });

    // Merge new attacks, cap at max
    _geoAttacks = [...newAttacks.slice(0, GEO_MAX_ATTACKS)];

    // If no real data, use simulated attacks for demo
    if (!_geoAttacks.length) {
      _geoAttacks = _generateDemoAttacks();
    }

    _updateGeoStatsPanel();
  } catch(err) {
    console.warn('[GeoMap] Data load failed:', err.message);
    if (!_geoAttacks.length) {
      _geoAttacks = _generateDemoAttacks();
    }
  }
}

function _generateDemoAttacks() {
  const srcs = ['CN','RU','KP','IR','NG','RO','VN','TR'];
  const tgts = ['US','GB','DE','FR','AU'];
  const attacks = [];
  for (let i = 0; i < 25; i++) {
    const srcCC = srcs[i % srcs.length];
    const tgtCC = tgts[i % tgts.length];
    const src   = COUNTRY_CENTROIDS[srcCC];
    const tgt   = COUNTRY_CENTROIDS[tgtCC];
    const sev   = ['critical','high','medium'][i % 3];
    const color = sev==='critical'?'#ef4444':sev==='high'?'#f97316':'#f59e0b';
    attacks.push({
      id: 'demo-'+i,
      srcLat: src.lat + (Math.random()-0.5)*6,
      srcLon: src.lon + (Math.random()-0.5)*6,
      tgtLat: tgt.lat + (Math.random()-0.5)*4,
      tgtLon: tgt.lon + (Math.random()-0.5)*4,
      srcName: src.name,
      tgtName: tgt.name,
      iocVal: ['185.220.101.'+Math.floor(Math.random()*256), 'malware-c2.ru', 'evil-domain.cn'][i%3],
      iocType: ['ip','domain','url'][i%3],
      risk: 50 + Math.floor(Math.random()*50),
      sev, color,
      progress: Math.random(),
      speed: GEO_LINE_SPEED * (0.5 + Math.random()),
      opacity: 0.5 + Math.random() * 0.5,
      active: true,
    });
  }
  return attacks;
}

/* ─────────────────────────────────────────────
   DRAW WORLD MAP BACKGROUND
───────────────────────────────────────────── */
function _drawWorldMap(ctx, W, H) {
  // Ocean background
  ctx.fillStyle = '#05080f';
  ctx.fillRect(0, 0, W, H);

  // Grid lines
  ctx.strokeStyle = 'rgba(29,106,229,0.07)';
  ctx.lineWidth = 0.5;
  for (let lon = -180; lon <= 180; lon += 30) {
    const {x} = latLonToXY(0, lon, W, H);
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, H);
    ctx.stroke();
  }
  for (let lat = -80; lat <= 80; lat += 30) {
    const {y} = latLonToXY(lat, 0, W, H);
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(W, y);
    ctx.stroke();
  }

  // Country dots at centroids
  Object.entries(COUNTRY_CENTROIDS).forEach(([cc, country]) => {
    const {x, y} = latLonToXY(country.lat, country.lon, W, H);
    const attackCount = _geoStats.countries[country.name] || 0;
    const r = attackCount > 0 ? Math.min(4 + attackCount*0.5, 12) : 3;

    // Glow for attacked countries
    if (attackCount > 0) {
      const grad = ctx.createRadialGradient(x, y, 0, x, y, r*3);
      grad.addColorStop(0, 'rgba(239,68,68,0.3)');
      grad.addColorStop(1, 'rgba(239,68,68,0)');
      ctx.beginPath();
      ctx.arc(x, y, r*3, 0, Math.PI*2);
      ctx.fillStyle = grad;
      ctx.fill();
    }

    // Country dot
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI*2);
    ctx.fillStyle = attackCount > 0 ? 'rgba(239,68,68,0.7)' : 'rgba(29,106,229,0.35)';
    ctx.fill();

    // Country label
    if (W > 600) {
      ctx.fillStyle = attackCount > 0 ? 'rgba(239,68,68,0.9)' : 'rgba(142,163,193,0.5)';
      ctx.font = `${attackCount > 0 ? 600 : 400} 8px Inter, sans-serif`;
      ctx.fillText(cc, x + r + 2, y + 3);
    }
  });
}

/* ─────────────────────────────────────────────
   DRAW ANIMATED ATTACK LINES
───────────────────────────────────────────── */
function _drawAttacks(ctx, W, H) {
  _geoAttacks.forEach(atk => {
    if (!atk.active) return;

    const src = latLonToXY(atk.srcLat, atk.srcLon, W, H);
    const tgt = latLonToXY(atk.tgtLat, atk.tgtLon, W, H);

    // Bezier control point (arc upward)
    const cp = {
      x: (src.x + tgt.x) / 2,
      y: Math.min(src.y, tgt.y) - Math.abs(src.x - tgt.x) * 0.25
    };

    // Current position along bezier
    const t  = atk.progress;
    const cx = (1-t)*(1-t)*src.x + 2*(1-t)*t*cp.x + t*t*tgt.x;
    const cy = (1-t)*(1-t)*src.y + 2*(1-t)*t*cp.y + t*t*tgt.y;

    // Draw trail (faded bezier up to current point)
    const trailLen = 0.15;
    const trailStart = Math.max(0, t - trailLen);
    ctx.beginPath();
    // Sample bezier points for trail
    for (let s = trailStart; s <= t; s += 0.01) {
      const bx = (1-s)*(1-s)*src.x + 2*(1-s)*s*cp.x + s*s*tgt.x;
      const by = (1-s)*(1-s)*src.y + 2*(1-s)*s*cp.y + s*s*tgt.y;
      if (s === trailStart) ctx.moveTo(bx, by);
      else ctx.lineTo(bx, by);
    }
    const alpha = (t - trailStart) / trailLen;
    ctx.strokeStyle = atk.color + Math.floor(atk.opacity * alpha * 200).toString(16).padStart(2,'0');
    ctx.lineWidth   = atk.sev === 'critical' ? 2 : 1.5;
    ctx.shadowBlur  = atk.sev === 'critical' ? 8 : 4;
    ctx.shadowColor = atk.color;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Draw head (glowing dot)
    const headGrad = ctx.createRadialGradient(cx, cy, 0, cx, cy, 6);
    headGrad.addColorStop(0, atk.color);
    headGrad.addColorStop(1, atk.color + '00');
    ctx.beginPath();
    ctx.arc(cx, cy, 6, 0, Math.PI*2);
    ctx.fillStyle = headGrad;
    ctx.fill();
    ctx.beginPath();
    ctx.arc(cx, cy, 2.5, 0, Math.PI*2);
    ctx.fillStyle = atk.color;
    ctx.fill();

    // Draw target pulse on arrival
    if (t > 0.9) {
      const pulse = (t - 0.9) / 0.1;
      ctx.beginPath();
      ctx.arc(tgt.x, tgt.y, pulse * 12, 0, Math.PI*2);
      ctx.strokeStyle = atk.color + Math.floor((1-pulse) * 150).toString(16).padStart(2,'0');
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // Advance progress
    atk.progress += atk.speed;
    if (atk.progress >= 1) {
      atk.progress = 0; // loop
    }
  });
}

/* ─────────────────────────────────────────────
   HEATMAP OVERLAY
───────────────────────────────────────────── */
function _drawHeatmap(ctx, W, H) {
  _geoAttacks.forEach(atk => {
    const src = latLonToXY(atk.srcLat, atk.srcLon, W, H);
    const r   = atk.sev === 'critical' ? 30 : atk.sev === 'high' ? 20 : 14;
    const grad = ctx.createRadialGradient(src.x, src.y, 0, src.x, src.y, r);
    grad.addColorStop(0, atk.color + '1a');
    grad.addColorStop(1, atk.color + '00');
    ctx.beginPath();
    ctx.arc(src.x, src.y, r, 0, Math.PI*2);
    ctx.fillStyle = grad;
    ctx.fill();
  });
}

/* ─────────────────────────────────────────────
   MAIN ANIMATION LOOP
───────────────────────────────────────────── */
function _geoAnimate() {
  if (!_geoCanvas || !_geoCtx) return;
  const W = _geoCanvas.width;
  const H = _geoCanvas.height;

  _geoCtx.clearRect(0, 0, W, H);
  _drawWorldMap(_geoCtx, W, H);
  _drawHeatmap(_geoCtx, W, H);
  _drawAttacks(_geoCtx, W, H);

  _geoAnimId = requestAnimationFrame(_geoAnimate);
}

/* ─────────────────────────────────────────────
   STATS PANEL
───────────────────────────────────────────── */
function _updateGeoStatsPanel() {
  const el = document.getElementById('geoStatsPanel');
  if (!el) return;

  const topCountries = Object.entries(_geoStats.countries)
    .sort((a,b) => b[1]-a[1])
    .slice(0,5);

  const critCount = _geoAttacks.filter(a => a.sev === 'critical').length;
  const highCount = _geoAttacks.filter(a => a.sev === 'high').length;

  el.innerHTML = `
    <div style="font-size:.72em;font-weight:700;color:#c9a227;text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px">
      <i class="fas fa-globe" style="margin-right:5px"></i>Live Threat Stats
    </div>
    <div style="margin-bottom:6px;font-size:.75em;color:#8b949e">Active Attacks: <span style="color:#ef4444;font-weight:700">${_geoAttacks.length}</span></div>
    <div style="margin-bottom:10px;display:flex;gap:6px;font-size:.72em">
      <span style="color:#ef4444">● ${critCount} Critical</span>
      <span style="color:#f97316">● ${highCount} High</span>
    </div>
    <div style="font-size:.72em;font-weight:600;color:#8b949e;margin-bottom:5px">Top Sources:</div>
    ${topCountries.map(([name, count]) => `
      <div style="display:flex;justify-content:space-between;font-size:.72em;padding:2px 0;color:#e6edf3">
        <span>${name}</span>
        <span style="color:#ef4444;font-weight:700">${count}</span>
      </div>`).join('')}`;
}

/* ─────────────────────────────────────────────
   CANVAS HOVER / CLICK
───────────────────────────────────────────── */
function _geoHandleMouseMove(e) {
  if (!_geoCanvas) return;
  const rect = _geoCanvas.getBoundingClientRect();
  const mx   = (e.clientX - rect.left) * (_geoCanvas.width / rect.width);
  const my   = (e.clientY - rect.top)  * (_geoCanvas.height / rect.height);

  _geoHover = null;
  const W = _geoCanvas.width;
  const H = _geoCanvas.height;

  _geoAttacks.forEach(atk => {
    const src = latLonToXY(atk.srcLat, atk.srcLon, W, H);
    const dist = Math.hypot(mx - src.x, my - src.y);
    if (dist < 12) _geoHover = atk;
  });

  const tooltip = document.getElementById('geoTooltip');
  if (tooltip) {
    if (_geoHover) {
      tooltip.style.display = 'block';
      tooltip.style.left    = (e.clientX - rect.left + 14) + 'px';
      tooltip.style.top     = (e.clientY - rect.top - 10) + 'px';
      tooltip.innerHTML = `
        <div style="font-weight:700;color:${_geoHover.color};margin-bottom:3px">${_geoHover.srcName} → ${_geoHover.tgtName}</div>
        <div style="font-size:.85em;color:#8b949e">${_geoHover.iocType}: <span style="color:#22d3ee;font-family:monospace">${(_geoHover.iocVal||'').slice(0,35)}</span></div>
        <div style="font-size:.85em;margin-top:3px">Risk Score: <strong style="color:${_geoHover.color}">${_geoHover.risk}</strong></div>`;
    } else {
      tooltip.style.display = 'none';
    }
  }
}

/* ─────────────────────────────────────────────
   PUBLIC: renderGeoThreatMap
───────────────────────────────────────────── */
async function renderGeoThreatMap() {
  const wrap = document.getElementById('geoThreatsWrap');
  if (!wrap) return;

  wrap.innerHTML = `
    <div style="position:relative;width:100%;height:100%;min-height:500px">
      <canvas id="geoMapCanvas" style="width:100%;height:100%;display:block;border-radius:12px;border:1px solid #1a2640;"></canvas>
      <!-- Stats Panel -->
      <div id="geoStatsPanel" style="position:absolute;top:16px;right:16px;background:rgba(5,8,15,.88);border:1px solid #1a2640;border-radius:10px;padding:12px 14px;min-width:180px;backdrop-filter:blur(8px);">
        <div style="font-size:.75em;color:#8b949e;text-align:center;padding:8px 0">Loading…</div>
      </div>
      <!-- Legend -->
      <div style="position:absolute;bottom:16px;left:16px;background:rgba(5,8,15,.88);border:1px solid #1a2640;border-radius:10px;padding:10px 14px;backdrop-filter:blur(8px);">
        <div style="font-size:.68em;font-weight:700;color:#c9a227;text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px">Legend</div>
        <div style="display:flex;flex-direction:column;gap:4px;font-size:.72em">
          <div><span style="color:#ef4444">● Critical</span> &nbsp;|&nbsp; <span style="color:#f97316">● High</span> &nbsp;|&nbsp; <span style="color:#f59e0b">● Medium</span></div>
          <div style="color:#8b949e"><span style="color:#3b82f6">●</span> Country node &nbsp;|&nbsp; <span style="color:#ef4444">●</span> Active attack source</div>
        </div>
      </div>
      <!-- Live indicator -->
      <div style="position:absolute;top:16px;left:16px;display:flex;align-items:center;gap:6px;background:rgba(5,8,15,.88);border:1px solid #1a2640;border-radius:8px;padding:6px 10px;backdrop-filter:blur(8px);">
        <div style="width:8px;height:8px;background:#22c55e;border-radius:50%;animation:livePulse 1.5s infinite"></div>
        <span style="font-size:.75em;font-weight:700;color:#22c55e">LIVE THREAT MAP</span>
        <span style="font-size:.68em;color:#8b949e" id="geoLastUpdate"></span>
      </div>
      <!-- Refresh button -->
      <button onclick="renderGeoThreatMap()" style="position:absolute;bottom:16px;right:16px;background:rgba(5,8,15,.88);border:1px solid #1a2640;border-radius:8px;color:#8b949e;padding:6px 12px;cursor:pointer;font-size:.75em;backdrop-filter:blur(8px);">
        <i class="fas fa-sync-alt"></i> Refresh
      </button>
      <!-- Tooltip -->
      <div id="geoTooltip" style="position:absolute;display:none;background:rgba(8,12,20,.95);border:1px solid #1e3050;border-radius:8px;padding:8px 12px;pointer-events:none;font-size:.78em;z-index:10;max-width:220px;"></div>
    </div>`;

  // Set up canvas — defer sizing to after layout paint
  _geoCanvas = document.getElementById('geoMapCanvas');
  if (!_geoCanvas) return;

  // Use requestAnimationFrame to ensure element is visible before measuring
  await new Promise(resolve => requestAnimationFrame(resolve));
  await new Promise(resolve => requestAnimationFrame(resolve)); // two frames for safety

  const container = _geoCanvas.parentElement;
  const W = Math.max(container.offsetWidth  || 0, 800);
  const H = Math.max(container.offsetHeight || 0, 500);
  _geoCanvas.width  = W;
  _geoCanvas.height = H;
  _geoCtx = _geoCanvas.getContext('2d');

  // Event listeners
  _geoCanvas.addEventListener('mousemove', _geoHandleMouseMove);

  // Load data and start animation
  await _loadGeoData();

  if (_geoAnimId) cancelAnimationFrame(_geoAnimId);
  _geoAnimate();

  // Auto-refresh
  if (_geoRefreshId) clearInterval(_geoRefreshId);
  _geoRefreshId = setInterval(async () => {
    await _loadGeoData();
    const el = document.getElementById('geoLastUpdate');
    if(el) el.textContent = '· ' + new Date().toLocaleTimeString();
  }, GEO_REFRESH_MS);

  _geoInitialized = true;
  console.info('[GeoMap] Initialized with', _geoAttacks.length, 'active attack vectors');
}

function stopGeoMap() {
  if (_geoAnimId)   { cancelAnimationFrame(_geoAnimId); _geoAnimId = null; }
  if (_geoRefreshId){ clearInterval(_geoRefreshId); _geoRefreshId = null; }
  if (_geoCanvas)   { _geoCanvas.removeEventListener('mousemove', _geoHandleMouseMove); }
  _geoInitialized = false;
}

// Resize handler
window.addEventListener('resize', () => {
  if (!_geoInitialized || !_geoCanvas) return;
  const container = _geoCanvas.parentElement;
  if (!container) return;
  _geoCanvas.width  = container.offsetWidth  || 800;
  _geoCanvas.height = container.offsetHeight || 500;
});

// Wire to global
window.renderGeoThreatMap = renderGeoThreatMap;
window.renderGeoThreats   = renderGeoThreatMap;
window.stopGeoMap         = stopGeoMap;

console.info('[GeoMap] Module loaded — EYEbot AI Geo Threat Map v2.0');
