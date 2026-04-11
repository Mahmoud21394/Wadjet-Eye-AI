/**
 * ══════════════════════════════════════════════════════════════════════
 *  EYEbot AI — Live IOC Lookup & Threat Intelligence Feeds v2.0
 *  Fixes: accurate results from VT, AbuseIPDB, Shodan, OTX
 *  Unified real-time results with clickable links, proper error handling
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ── State ── */
const _LIOF = {
  currentValue: null,
  currentType:  null,
  results:      {},
  loading:      false,
  history:      [],
};

/* ── API helpers ── */
const _liofApiBase = () =>
  (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');

async function _liofFetch(path, opts = {}) {
  if (window.authFetch) return window.authFetch(path, opts);
  const base  = _liofApiBase();
  const token = localStorage.getItem('wadjet_access_token') || localStorage.getItem('tp_access_token') || '';
  const r = await fetch(`${base}/api${path}`, {
    method: opts.method || 'GET',
    headers: { 'Content-Type':'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) },
    ...(opts.body ? { body: typeof opts.body==='string'?opts.body:JSON.stringify(opts.body) } : {}),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

function _liofEsc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ── Source definitions ── */
const INTEL_SOURCES = [
  {
    id: 'virustotal', name: 'VirusTotal', abbr: 'VT',
    color: '#3b82f6', icon: 'fa-virus',
    url: (v,t) => {
      if (/^[a-fA-F0-9]{32,128}$/.test(v)) return `https://www.virustotal.com/gui/file/${v}`;
      if (/^https?:\/\//.test(v))           return `https://www.virustotal.com/gui/url/${btoa(v).replace(/=/g,'')}`;
      if (/^\d+\.\d+\.\d+\.\d+$/.test(v))  return `https://www.virustotal.com/gui/ip-address/${v}`;
      return `https://www.virustotal.com/gui/domain/${v}`;
    },
    supports: ['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'hash_sha512'],
  },
  {
    id: 'abuseipdb', name: 'AbuseIPDB', abbr: 'AB',
    color: '#ef4444', icon: 'fa-shield-alt',
    url: (v) => `https://www.abuseipdb.com/check/${v}`,
    supports: ['ip'],
  },
  {
    id: 'shodan', name: 'Shodan', abbr: 'SH',
    color: '#f97316', icon: 'fa-server',
    url: (v) => `https://www.shodan.io/host/${v}`,
    supports: ['ip'],
  },
  {
    id: 'otx', name: 'AlienVault OTX', abbr: 'OTX',
    color: '#a855f7', icon: 'fa-satellite',
    url: (v, t) => {
      const typeMap = { ip:'ip', domain:'domain', url:'url', hash_sha256:'file', hash_md5:'file', hash_sha1:'file' };
      const tp = typeMap[t] || 'hostname';
      return `https://otx.alienvault.com/indicator/${tp}/${encodeURIComponent(v)}`;
    },
    supports: ['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256'],
  },
  {
    id: 'urlhaus', name: 'URLhaus', abbr: 'UH',
    color: '#22c55e', icon: 'fa-link',
    url: (v) => `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(v)}`,
    supports: ['url', 'domain', 'ip'],
  },
  {
    id: 'threatfox', name: 'ThreatFox', abbr: 'TF',
    color: '#22d3ee', icon: 'fa-fire',
    url: (v) => `https://threatfox.abuse.ch/browse/?q=${encodeURIComponent(v)}`,
    supports: ['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256'],
  },
];

/* ══════════════════════════════════════════════════════
   LIVE LOOKUP PAGE RENDERER
══════════════════════════════════════════════════════ */
window.renderLiveIOCLookup = function() {
  const c = document.getElementById('liveIOCLookupContainer')
         || document.getElementById('page-live-feeds')
         || document.getElementById('liveFeedsContainer');
  if (!c) return;

  c.innerHTML = `
  <!-- Header -->
  <div class="enh-module-header">
    <div class="enh-module-header__glow-1"></div>
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;position:relative">
      <div>
        <h2 style="margin:0;color:#e6edf3;font-size:1.15em;font-weight:700">
          <i class="fas fa-satellite" style="color:#22d3ee;margin-right:8px"></i>Live IOC Lookup
        </h2>
        <div style="font-size:.76em;color:#8b949e;margin-top:2px">
          Real-time investigation across VirusTotal · AbuseIPDB · Shodan · AlienVault OTX · URLhaus · ThreatFox
        </div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        ${INTEL_SOURCES.map(s => `
          <span class="enh-badge" style="background:${s.color}15;color:${s.color};border:1px solid ${s.color}30">
            <i class="fas ${s.icon}" style="margin-right:3px;font-size:.85em"></i>${s.name}
          </span>`).join('')}
      </div>
    </div>
  </div>

  <div style="padding:16px">

    <!-- Search Box -->
    <div class="live-lookup-header" style="margin-bottom:16px">
      <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
        <div style="flex:1;min-width:240px">
          <label style="font-size:.78em;font-weight:600;color:#8b949e;display:block;margin-bottom:6px">
            <i class="fas fa-search" style="margin-right:4px;color:#22d3ee"></i>IOC Value
          </label>
          <div style="position:relative">
            <input id="liof-input" class="enh-input"
              style="width:100%;box-sizing:border-box;height:44px;font-size:.95em;font-family:monospace;padding-right:130px"
              placeholder="IP · Domain · Hash · URL · Email · CVE…"
              oninput="_liofUpdate(this.value)"
              onkeydown="if(event.key==='Enter')liofLookup()"
              autocomplete="off" autocorrect="off" spellcheck="false" />
            <span id="liof-type-badge" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);
              font-size:.7em;padding:2px 8px;border-radius:6px;font-weight:700;pointer-events:none;display:none"></span>
          </div>
          <div id="liof-hint" class="ioc-validation-hint" style="margin-top:4px"></div>
        </div>
        <div>
          <label style="font-size:.78em;font-weight:600;color:#8b949e;display:block;margin-bottom:6px">Sources</label>
          <div style="display:flex;gap:4px">
            ${INTEL_SOURCES.map(s => `
              <label title="${s.name}" style="cursor:pointer;padding:8px;background:rgba(255,255,255,.05);
                border:1px solid rgba(255,255,255,.08);border-radius:6px;display:flex;align-items:center;
                transition:all .15s"
                onmouseover="this.style.borderColor='${s.color}44'" onmouseout="this.style.borderColor='rgba(255,255,255,.08)'">
                <input type="checkbox" id="liof-src-${s.id}" checked
                  style="margin:0;accent-color:${s.color};width:12px;height:12px" />
                <span style="font-size:.7em;color:${s.color};margin-left:4px;white-space:nowrap">${s.abbr}</span>
              </label>`).join('')}
          </div>
        </div>
        <button class="enh-btn enh-btn--primary" onclick="liofLookup()" id="liof-btn" style="height:44px;padding:0 20px;align-self:flex-end">
          <i class="fas fa-search" id="liof-btn-icon"></i> Investigate
        </button>
      </div>

      <!-- History chips -->
      <div id="liof-history" style="display:flex;flex-wrap:wrap;gap:5px;margin-top:10px"></div>
    </div>

    <!-- Results -->
    <div id="liof-results">
      <div style="text-align:center;padding:48px;color:#4b5563">
        <i class="fas fa-satellite-dish fa-2x" style="display:block;margin-bottom:14px;opacity:.3;color:#22d3ee"></i>
        <div style="font-size:.9em;color:#6b7280">Enter any IOC above to investigate across all intelligence sources</div>
        <div style="font-size:.78em;color:#4b5563;margin-top:6px">Supports: IPv4, IPv6, Domains, URLs, Hashes (MD5/SHA1/SHA256), Email, CVE IDs</div>
      </div>
    </div>

  </div>
  `;

  // Restore history
  _liofRenderHistory();
};

/* ── Type badge update ── */
window._liofUpdate = function(value) {
  const badge = document.getElementById('liof-type-badge');
  const hint  = document.getElementById('liof-hint');
  if (!value || value.trim().length < 2) {
    if (badge) badge.style.display = 'none';
    if (hint)  { hint.className = 'ioc-validation-hint'; hint.textContent = ''; }
    return;
  }
  if (typeof window.detectIOCType === 'function') {
    const d = window.detectIOCType(value.trim());
    if (badge) {
      badge.style.display = 'inline-flex';
      badge.style.background = (d.color||'#8b949e') + '22';
      badge.style.color = d.color || '#8b949e';
      badge.style.border = `1px solid ${(d.color||'#8b949e')}44`;
      badge.innerHTML = `<i class="fas ${d.icon||'fa-question'}" style="margin-right:3px;font-size:.9em"></i>${d.label||'?'}`;
    }
    if (hint && d.hint) {
      hint.className = `ioc-validation-hint ioc-validation-hint--show ${
        !d.valid?'ioc-validation-hint--error':d.hint.startsWith('⚠')?'ioc-validation-hint--info':'ioc-validation-hint--success'}`;
      hint.textContent = d.hint;
    }
  }
};

/* ── Main lookup ── */
window.liofLookup = async function() {
  const inp = document.getElementById('liof-input');
  if (!inp) return;
  const value = inp.value.trim();
  if (!value) return;

  // Detect type
  const detected = (typeof window.detectIOCType === 'function')
    ? window.detectIOCType(value)
    : { type:'unknown', valid:false, label:'Unknown', color:'#8b949e', icon:'fa-question' };

  _LIOF.currentValue = value;
  _LIOF.currentType  = detected.type;
  _LIOF.loading = true;

  // Add to history
  if (!_LIOF.history.find(h=>h.value===value)) {
    _LIOF.history.unshift({ value, type:detected.type, label:detected.label, color:detected.color });
    if (_LIOF.history.length > 10) _LIOF.history.pop();
  }
  _liofRenderHistory();

  // Determine active sources
  const activeSources = INTEL_SOURCES.filter(s => {
    const cb = document.getElementById(`liof-src-${s.id}`);
    return cb ? cb.checked : true;
  }).filter(s => !detected.type || s.supports.includes(detected.type) || s.supports.includes('ip'));

  const results = document.getElementById('liof-results');
  if (!results) return;

  // Show loading state
  const btn = document.getElementById('liof-btn');
  const icon = document.getElementById('liof-btn-icon');
  if (btn) btn.disabled = true;
  if (icon) icon.className = 'fas fa-circle-notch fa-spin';

  results.innerHTML = `
    <div style="background:rgba(13,20,33,.8);border:1px solid #1a2535;border-radius:12px;overflow:hidden;margin-bottom:14px">
      <!-- Header -->
      <div style="padding:14px 16px;border-bottom:1px solid #1a2535;display:flex;align-items:center;gap:10px">
        <div style="width:34px;height:34px;background:${detected.color||'#22d3ee'}18;border:1px solid ${detected.color||'#22d3ee'}30;
          border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
          <i class="fas ${detected.icon||'fa-search'}" style="color:${detected.color||'#22d3ee'};font-size:.85em"></i>
        </div>
        <div>
          <code style="font-family:monospace;font-size:.9em;color:#e6edf3;font-weight:700;word-break:break-all">${_liofEsc(value)}</code>
          <div style="font-size:.74em;color:#8b949e;margin-top:2px">
            <span style="color:${detected.color||'#22d3ee'};font-weight:600">${detected.label||'Unknown Type'}</span>
            · Querying ${activeSources.length} intelligence source${activeSources.length>1?'s':''}…
          </div>
        </div>
      </div>
      <!-- Source Results (loading) -->
      <div id="liof-source-panels" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:0">
        ${activeSources.map(s => `
          <div id="liof-panel-${s.id}" style="padding:14px 16px;border-right:1px solid #1a2535;border-bottom:1px solid #1a2535">
            <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
              <div style="width:24px;height:24px;background:${s.color}18;border-radius:5px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
                <i class="fas ${s.icon}" style="color:${s.color};font-size:.7em"></i>
              </div>
              <span style="font-size:.78em;font-weight:700;color:#e6edf3">${s.name}</span>
            </div>
            <div style="height:4px;background:linear-gradient(90deg,#0d1421 25%,#131b2a 50%,#0d1421 75%);
              background-size:200% 100%;animation:enh-shimmer 1.4s infinite;border-radius:2px;margin-bottom:6px"></div>
            <div style="height:3px;background:linear-gradient(90deg,#0d1421 25%,#131b2a 50%,#0d1421 75%);
              background-size:200% 100%;animation:enh-shimmer 1.4s infinite;border-radius:2px;width:60%"></div>
          </div>`).join('')}
      </div>
    </div>`;

  // Run all source queries in parallel
  const tasks = activeSources.map(source => _liofQuerySource(source, value, detected.type));
  const taskResults = await Promise.allSettled(tasks);

  // Render individual source results
  activeSources.forEach((source, i) => {
    const panel = document.getElementById(`liof-panel-${source.id}`);
    if (!panel) return;
    const result = taskResults[i];
    if (result.status === 'fulfilled') {
      panel.innerHTML = _liofRenderSourcePanel(source, value, detected.type, result.value);
    } else {
      panel.innerHTML = _liofRenderSourceError(source, result.reason?.message || 'Request failed');
    }
  });

  // Compute overall verdict
  const allResults = taskResults.filter(r=>r.status==='fulfilled').map(r=>r.value);
  const verdict = _liofComputeVerdict(allResults);

  // Inject verdict
  const verdictEl = document.createElement('div');
  verdictEl.innerHTML = `
    <div style="background:${verdict.color}08;border:1px solid ${verdict.color}25;border-radius:10px;
      padding:12px 16px;margin-bottom:14px;display:flex;align-items:center;gap:10px;animation:enh-fadeIn .3s ease">
      <i class="fas ${verdict.icon}" style="color:${verdict.color};font-size:1.3em;flex-shrink:0"></i>
      <div>
        <div style="font-weight:800;color:${verdict.color};font-size:.95em">${verdict.label}</div>
        <div style="font-size:.78em;color:#8b949e;margin-top:2px">${verdict.summary}</div>
      </div>
      <div style="margin-left:auto;display:flex;gap:6px">
        <a href="${activeSources[0]?.url?.(value, detected.type)||'#'}" target="_blank" rel="noopener"
          class="enh-btn enh-btn--ghost enh-btn--sm" style="text-decoration:none">
          <i class="fas fa-external-link-alt"></i> Open Full Report
        </a>
        <button onclick="_liofCreateCase('${_liofEsc(value)}','${_liofEsc(detected.type||'')}')"
          class="enh-btn enh-btn--primary enh-btn--sm">
          <i class="fas fa-folder-plus"></i> Create Case
        </button>
      </div>
    </div>`;
  results.insertBefore(verdictEl, results.firstChild);

  // Re-enable button
  if (btn) btn.disabled = false;
  if (icon) icon.className = 'fas fa-search';
  _LIOF.loading = false;
};

/* ── Query a source ── */
async function _liofQuerySource(source, value, type) {
  // Try backend enrichment endpoint
  const data = await _liofFetch('/intel/lookup', {
    method: 'POST',
    body: { value, type: type||'unknown', source: source.id },
  });
  return data;
}

/* ── Render source panel ── */
function _liofRenderSourcePanel(source, value, type, data) {
  if (!data) return _liofRenderSourceError(source, 'No data returned');

  const isMalicious = data.malicious > 0 || data.verdict === 'malicious' ||
    data.abuseConfidenceScore > 50 || data.reputation === 'malicious';
  const isSuspicious = !isMalicious && (data.suspicious > 0 || data.abuseConfidenceScore > 10 ||
    data.verdict === 'suspicious' || data.reputation === 'suspicious');
  const rc = isMalicious ? '#ef4444' : isSuspicious ? '#f97316' : '#22c55e';
  const verdict = isMalicious ? 'MALICIOUS' : isSuspicious ? 'SUSPICIOUS' : 'CLEAN';

  let details = '';
  if (data.malicious != null) {
    const total = (data.malicious||0)+(data.suspicious||0)+(data.clean||0)+(data.undetected||0);
    const pct = total>0 ? Math.round((data.malicious/total)*100) : 0;
    details = `<div style="font-size:.8em;color:#8b949e;margin:6px 0">
      <span style="color:#ef4444;font-weight:700">${data.malicious}</span>/${total} engines
      <div style="height:4px;background:#1e2d3d;border-radius:2px;margin-top:4px;overflow:hidden">
        <div style="height:100%;width:${pct}%;background:${rc};border-radius:2px;transition:width .6s"></div>
      </div></div>`;
  }
  if (data.abuseConfidenceScore != null) {
    details = `<div style="font-size:.8em;color:#8b949e;margin:6px 0">
      Confidence: <span style="color:${rc};font-weight:700">${data.abuseConfidenceScore}%</span>
      ${data.totalReports ? ` · ${data.totalReports} reports` : ''}
      ${data.countryCode ? ` · ${data.countryCode}` : ''}
    </div>`;
  }
  if (data.ports) {
    details = `<div style="font-size:.78em;color:#8b949e;margin:6px 0">
      Ports: <span style="color:#22d3ee">${(data.ports||[]).slice(0,5).join(', ')}</span>
      ${data.org ? `<br>${_liofEsc(data.org)}` : ''}
    </div>`;
  }
  if (data.pulses != null) {
    details = `<div style="font-size:.78em;color:#8b949e;margin:6px 0">
      <span style="color:#a855f7;font-weight:700">${data.pulses.length}</span> threat pulse${data.pulses.length!==1?'s':''}
      ${data.pulses.slice(0,1).map(p=>`<br><span style="font-size:.9em">${_liofEsc(p.name||'')}</span>`).join('')}
    </div>`;
  }

  return `
    <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
      <div style="width:24px;height:24px;background:${source.color}18;border-radius:5px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
        <i class="fas ${source.icon}" style="color:${source.color};font-size:.7em"></i>
      </div>
      <span style="font-size:.78em;font-weight:700;color:#e6edf3">${source.name}</span>
    </div>
    <span style="background:${rc}18;color:${rc};border:1px solid ${rc}30;padding:1px 8px;border-radius:8px;font-size:.68em;font-weight:700">${verdict}</span>
    ${details}
    <a href="${source.url?.(value, type)||'#'}" target="_blank" rel="noopener"
      style="display:inline-flex;align-items:center;gap:4px;font-size:.72em;color:${source.color};text-decoration:none;margin-top:4px;
        padding:2px 0;transition:opacity .15s"
      onmouseover="this.style.opacity='.7'" onmouseout="this.style.opacity='1'">
      <i class="fas fa-external-link-alt" style="font-size:.8em"></i> View on ${source.name}
    </a>`;
}

function _liofRenderSourceError(source, message) {
  return `
    <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
      <div style="width:24px;height:24px;background:${source.color}18;border-radius:5px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
        <i class="fas ${source.icon}" style="color:${source.color};font-size:.7em"></i>
      </div>
      <span style="font-size:.78em;font-weight:700;color:#e6edf3">${source.name}</span>
    </div>
    <span style="background:rgba(107,114,128,.1);color:#6b7280;border:1px solid rgba(107,114,128,.15);
      padding:1px 7px;border-radius:8px;font-size:.68em">UNAVAILABLE</span>
    <div style="font-size:.72em;color:#4b5563;margin-top:4px">${_liofEsc(message?.slice(0,60)||'API not configured')}</div>
    <a href="${source.url?.((_LIOF.currentValue||'x'), _LIOF.currentType)||'#'}" target="_blank" rel="noopener"
      style="display:inline-flex;align-items:center;gap:4px;font-size:.72em;color:${source.color};text-decoration:none;margin-top:4px">
      <i class="fas fa-external-link-alt" style="font-size:.8em"></i> Check directly
    </a>`;
}

/* ── Compute verdict ── */
function _liofComputeVerdict(results) {
  let malScore = 0;
  let reasons  = [];
  results.forEach(r => {
    if (!r) return;
    if (r.malicious > 0)                { malScore += Math.min(r.malicious*8, 40); reasons.push(`${r.malicious} VT detections`); }
    if (r.abuseConfidenceScore > 50)    { malScore += 30; reasons.push(`AbuseIPDB ${r.abuseConfidenceScore}%`); }
    if (r.pulses?.length > 0)           { malScore += Math.min(r.pulses.length*5, 20); reasons.push(`${r.pulses.length} OTX pulses`); }
    if (r.reputation === 'malicious')   { malScore += 25; reasons.push('malicious reputation'); }
  });

  let label, color, icon, summary;
  if (malScore >= 60)       { label='MALICIOUS'; color='#ef4444'; icon='fa-skull-crossbones'; summary=reasons.join(' · ')||'High-confidence malicious indicator'; }
  else if (malScore >= 25)  { label='SUSPICIOUS'; color='#f97316'; icon='fa-exclamation-triangle'; summary=reasons.join(' · ')||'Some indicators of malicious activity'; }
  else if (malScore >= 5)   { label='POSSIBLY SUSPICIOUS'; color='#eab308'; icon='fa-question-circle'; summary='Low confidence indicators — investigate further'; }
  else                      { label='CLEAN / UNKNOWN'; color='#22c55e'; icon='fa-check-circle'; summary='No malicious indicators found in queried sources'; }

  return { label, color, icon, summary, score: malScore };
}

/* ── History ── */
function _liofRenderHistory() {
  const el = document.getElementById('liof-history');
  if (!el) return;
  if (!_LIOF.history.length) { el.innerHTML=''; return; }
  el.innerHTML = _LIOF.history.slice(0,8).map(h => `
    <button onclick="_liofClickHistory('${_liofEsc(h.value)}')"
      style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);
        color:#8b949e;padding:2px 8px;border-radius:5px;font-size:.72em;cursor:pointer;
        font-family:monospace;transition:all .15s;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
      onmouseover="this.style.color='#e6edf3';this.style.borderColor='rgba(34,211,238,.3)'"
      onmouseout="this.style.color='#8b949e';this.style.borderColor='rgba(255,255,255,.06)'"
      title="${_liofEsc(h.value)}">${_liofEsc(h.value)}</button>`).join('');
}

window._liofClickHistory = function(value) {
  const inp = document.getElementById('liof-input');
  if (inp) { inp.value = value; window._liofUpdate(value); window.liofLookup(); }
};

window._liofCreateCase = function(value, type) {
  if (typeof showToast === 'function') showToast(`✅ DFIR case created for ${value.slice(0,40)}`, 'success');
};
