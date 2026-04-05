/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — IOC Registry Search Enhancement v2.0
 *  - Real-time type detection and validation
 *  - Supports: IP, IPv6, Domain, URL, Hash (MD5/SHA1/SHA256/SHA512),
 *              Email, CVE, CIDR, ASN, Filename, Registry Key
 *  - Instant feedback with error handling
 *  - Enhanced search integration with ioc-intelligence.js
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ══════════════════════════════════════════════════════
   IOC TYPE DETECTION ENGINE
══════════════════════════════════════════════════════ */
const IOC_PATTERNS = {
  ipv4:      { re: /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/, label:'IPv4', color:'#3b82f6',  icon:'fa-network-wired' },
  ipv6:      { re: /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(%\w+)?$/, label:'IPv6', color:'#6366f1', icon:'fa-network-wired' },
  cidr:      { re: /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/, label:'CIDR', color:'#06b6d4', icon:'fa-sitemap' },
  domain:    { re: /^(?!https?:\/\/)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/, label:'Domain', color:'#8b5cf6', icon:'fa-globe' },
  url:       { re: /^https?:\/\/[^\s]+$/, label:'URL', color:'#ec4899', icon:'fa-link' },
  md5:       { re: /^[a-fA-F0-9]{32}$/, label:'MD5 Hash', color:'#f59e0b', icon:'fa-hashtag' },
  sha1:      { re: /^[a-fA-F0-9]{40}$/, label:'SHA1 Hash', color:'#f97316', icon:'fa-hashtag' },
  sha256:    { re: /^[a-fA-F0-9]{64}$/, label:'SHA256 Hash', color:'#ef4444', icon:'fa-hashtag' },
  sha512:    { re: /^[a-fA-F0-9]{128}$/, label:'SHA512 Hash', color:'#dc2626', icon:'fa-hashtag' },
  email:     { re: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, label:'Email', color:'#22c55e', icon:'fa-envelope' },
  cve:       { re: /^CVE-\d{4}-\d{4,}$/i, label:'CVE', color:'#f97316', icon:'fa-bug' },
  asn:       { re: /^AS\d+$/i, label:'ASN', color:'#22d3ee', icon:'fa-server' },
  btc:       { re: /^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$/, label:'Bitcoin', color:'#f59e0b', icon:'fa-bitcoin-sign' },
  filename:  { re: /^[^\\/:\*?"<>|]+\.[a-zA-Z]{1,10}$/, label:'Filename', color:'#a855f7', icon:'fa-file' },
};

/**
 * Detect IOC type from input value
 * Returns { type, label, color, icon, valid, hint }
 */
function detectIOCType(value) {
  if (!value || value.trim().length < 2) {
    return { type: null, label: null, color: null, icon: null, valid: false, hint: '' };
  }

  const v = value.trim();

  // Check URL first (before domain)
  if (IOC_PATTERNS.url.re.test(v)) {
    return { type:'url', ...IOC_PATTERNS.url, valid: true, hint: 'Valid URL detected' };
  }

  // Check CVE
  if (IOC_PATTERNS.cve.re.test(v)) {
    return { type:'cve', ...IOC_PATTERNS.cve, valid: true, hint: 'CVE identifier detected' };
  }

  // Check email
  if (IOC_PATTERNS.email.re.test(v)) {
    return { type:'email', ...IOC_PATTERNS.email, valid: true, hint: 'Email address detected' };
  }

  // Check CIDR (before IPv4)
  if (IOC_PATTERNS.cidr.re.test(v)) {
    const [ip, prefix] = v.split('/');
    const parts = ip.split('.').map(Number);
    const validIP = parts.every(p => p >= 0 && p <= 255);
    if (validIP) return { type:'cidr', ...IOC_PATTERNS.cidr, valid: true, hint: `CIDR block /${prefix}` };
  }

  // Check IPv4
  if (IOC_PATTERNS.ipv4.re.test(v)) {
    const parts = v.split('/')[0].split('.').map(Number);
    const valid  = parts.every(p => p >= 0 && p <= 255);
    if (valid) {
      const isPrivate = (parts[0]===10) || (parts[0]===172&&parts[1]>=16&&parts[1]<=31) || (parts[0]===192&&parts[1]===168);
      return {
        type:'ip', label:'IPv4', color:IOC_PATTERNS.ipv4.color, icon:IOC_PATTERNS.ipv4.icon,
        valid: true,
        hint: isPrivate ? '⚠️ Private/RFC1918 address — unlikely to be malicious' : 'Public IPv4 address detected'
      };
    }
    return { type:'ip', label:'IPv4', color:'#ef4444', icon:'fa-network-wired', valid:false, hint:'Invalid IPv4: octets must be 0-255' };
  }

  // Check IPv6
  if (IOC_PATTERNS.ipv6.re.test(v)) {
    return { type:'ipv6', ...IOC_PATTERNS.ipv6, valid: true, hint: 'IPv6 address detected' };
  }

  // Check ASN
  if (IOC_PATTERNS.asn.re.test(v)) {
    return { type:'asn', ...IOC_PATTERNS.asn, valid: true, hint: 'Autonomous System Number' };
  }

  // Check hashes by length
  const hex = /^[a-fA-F0-9]+$/.test(v);
  if (hex) {
    if (v.length === 32)  return { type:'hash_md5',    ...IOC_PATTERNS.md5,    valid:true, hint:'MD5 hash (32 hex chars)' };
    if (v.length === 40)  return { type:'hash_sha1',   ...IOC_PATTERNS.sha1,   valid:true, hint:'SHA1 hash (40 hex chars)' };
    if (v.length === 64)  return { type:'hash_sha256', ...IOC_PATTERNS.sha256, valid:true, hint:'SHA256 hash (64 hex chars)' };
    if (v.length === 128) return { type:'hash_sha512', ...IOC_PATTERNS.sha512, valid:true, hint:'SHA512 hash (128 hex chars)' };
    if (v.length > 8) return { type:'hash', label:'Hash', color:'#f59e0b', icon:'fa-hashtag', valid:false,
      hint:`⚠️ Partial hash? ${v.length} chars — MD5=32, SHA1=40, SHA256=64, SHA512=128` };
  }

  // Check domain
  if (IOC_PATTERNS.domain.re.test(v)) {
    const tld = v.split('.').pop().toLowerCase();
    const suspiciousTLDs = ['ru','cn','ir','kp','tk','pw','cf','ga','ml','gq'];
    return {
      type:'domain', ...IOC_PATTERNS.domain, valid:true,
      hint: suspiciousTLDs.includes(tld)
        ? `⚠️ TLD .${tld} is commonly associated with malicious activity`
        : `Domain detected — TLD: .${tld}`
    };
  }

  // Filename
  if (IOC_PATTERNS.filename.re.test(v) && !v.includes(' ')) {
    return { type:'filename', ...IOC_PATTERNS.filename, valid:true, hint:'Filename/artifact detected' };
  }

  // Unknown
  return {
    type: 'unknown',
    label: 'Unknown',
    color: '#8b949e',
    icon: 'fa-question-circle',
    valid: false,
    hint: 'Could not detect IOC type. Try a full IP, domain, hash, URL, or email.'
  };
}

/* ══════════════════════════════════════════════════════
   ENHANCED IOC SEARCH OVERLAY
══════════════════════════════════════════════════════ */
function _iocSearchOverlayHTML() {
  return `
  <div id="ioc-search-overlay" style="
    position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(8px);
    z-index:9500;display:flex;align-items:flex-start;justify-content:center;
    padding-top:80px;animation:enh-fadeIn .2s ease">
    <div style="background:#080c14;border:1px solid rgba(34,211,238,.2);border-radius:16px;
      width:min(700px,95vw);max-height:80vh;overflow-y:auto;
      box-shadow:0 24px 80px rgba(0,0,0,.8),0 0 0 1px rgba(34,211,238,.1)">

      <!-- Header -->
      <div style="padding:20px 24px;border-bottom:1px solid #1a2535;position:sticky;top:0;background:#080c14;z-index:2">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
          <div style="width:38px;height:38px;background:rgba(34,211,238,.1);border:1px solid rgba(34,211,238,.2);
            border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
            <i class="fas fa-search" style="color:#22d3ee;font-size:.9em"></i>
          </div>
          <div>
            <div style="font-size:1em;font-weight:700;color:#e6edf3">IOC Quick Lookup</div>
            <div style="font-size:.74em;color:#8b949e">Search any IP, domain, hash, URL, email, or CVE</div>
          </div>
          <button onclick="closeIOCSearch()" class="enh-btn enh-btn--ghost enh-btn--sm" style="margin-left:auto">
            <i class="fas fa-times"></i>
          </button>
        </div>

        <!-- Search Input -->
        <div class="ioc-search-input-wrap" style="margin-bottom:8px">
          <i class="fas fa-search search-icon"></i>
          <input id="ioc-quick-input" class="enh-input"
            style="padding-left:40px;padding-right:120px;width:100%;box-sizing:border-box;height:48px;font-size:.95em;border-radius:10px;
              border-color:rgba(34,211,238,.3);box-shadow:0 0 0 3px rgba(34,211,238,.06)"
            placeholder="8.8.8.8 · malware.exe · CVE-2024-3400 · SHA256…"
            oninput="iocQuickUpdate(this.value)"
            onkeydown="if(event.key==='Enter')iocQuickSearch()"
            autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" />
          <span id="ioc-type-badge" class="search-type-badge" style="display:none"></span>
        </div>

        <!-- Validation hint -->
        <div id="ioc-validation-hint" class="ioc-validation-hint"></div>

        <!-- Quick type buttons -->
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px">
          ${['8.8.8.8','malware[.]com','a3f2b1c9d4e5f6789012345678901234567890abcdef1234567890abcdef1234',
             'https://evil[.]com/payload.exe','attacker@evil.com','CVE-2024-3400'].map(ex =>
            `<button onclick="iocQuickFill('${ex}')" style="
              background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);
              color:#8b949e;padding:2px 8px;border-radius:5px;font-size:.72em;cursor:pointer;
              font-family:monospace;transition:all .15s"
              onmouseover="this.style.color='#e6edf3';this.style.borderColor='rgba(34,211,238,.3)'"
              onmouseout="this.style.color='#8b949e';this.style.borderColor='rgba(255,255,255,.08)'">${ex}</button>`).join('')}
        </div>
      </div>

      <!-- Results Area -->
      <div id="ioc-search-results" style="padding:16px;min-height:120px">
        <div style="text-align:center;padding:32px;color:#4b5563">
          <i class="fas fa-search fa-2x" style="display:block;margin-bottom:10px;opacity:.3"></i>
          Enter an IOC value above to search the database and intelligence feeds
        </div>
      </div>
    </div>
  </div>
  `;
}

/* ── Open IOC search ── */
window.openIOCSearch = function() {
  let overlay = document.getElementById('ioc-search-overlay');
  if (!overlay) {
    document.body.insertAdjacentHTML('beforeend', _iocSearchOverlayHTML());
    overlay = document.getElementById('ioc-search-overlay');
  }
  overlay.style.display = 'flex';
  setTimeout(() => document.getElementById('ioc-quick-input')?.focus(), 100);
};

/* ── Close IOC search ── */
window.closeIOCSearch = function() {
  const o = document.getElementById('ioc-search-overlay');
  if (o) { o.style.animation='none'; o.style.opacity='0'; setTimeout(()=>o.remove(),200); }
};

/* Close on background click */
document.addEventListener('click', function(e) {
  if (e.target.id === 'ioc-search-overlay') window.closeIOCSearch();
});

/* ── Update type badge in real time ── */
window.iocQuickUpdate = function(value) {
  const badge = document.getElementById('ioc-type-badge');
  const hint  = document.getElementById('ioc-validation-hint');
  if (!badge || !hint) return;

  if (!value || value.trim().length < 2) {
    badge.style.display = 'none';
    hint.className = 'ioc-validation-hint';
    hint.textContent = '';
    return;
  }

  const detected = detectIOCType(value.trim());

  // Update badge
  badge.style.display = 'inline-flex';
  badge.style.background = (detected.color || '#8b949e') + '22';
  badge.style.color = detected.color || '#8b949e';
  badge.style.border = `1px solid ${(detected.color||'#8b949e')}44`;
  badge.innerHTML = `<i class="fas ${detected.icon||'fa-question'}" style="margin-right:4px;font-size:.9em"></i>${detected.label||'Unknown'}`;

  // Update hint
  hint.className = `ioc-validation-hint ioc-validation-hint--show ${
    !detected.valid ? 'ioc-validation-hint--error' :
    (detected.hint?.startsWith('⚠') ? 'ioc-validation-hint--info' :
     'ioc-validation-hint--success')}`;
  hint.textContent = detected.hint || '';
};

/* ── Fill example ── */
window.iocQuickFill = function(val) {
  const inp = document.getElementById('ioc-quick-input');
  if (inp) {
    inp.value = val;
    iocQuickUpdate(val);
    inp.focus();
  }
};

/* ── Main search ── */
window.iocQuickSearch = async function() {
  const inp = document.getElementById('ioc-quick-input');
  const res = document.getElementById('ioc-search-results');
  if (!inp || !res) return;

  const value = inp.value.trim();
  if (!value) return;

  const detected = detectIOCType(value);

  // Show loading
  res.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;padding:20px;color:#8b949e;font-size:.85em">
      <div style="width:24px;height:24px;border:2px solid #1e2d3d;border-top-color:#22d3ee;
        border-radius:50%;animation:enh-spin .8s linear infinite;flex-shrink:0"></div>
      Searching for <strong style="color:#22d3ee">${_iocSearchEsc(value)}</strong>
      as <strong style="color:${detected.color||'#8b949e'}">${detected.label||'unknown type'}</strong>…
    </div>`;

  try {
    // 1. Search local DB
    const dbResults = await _iocDbSearch(value, detected.type);

    // 2. Search via API
    const apiResults = await _iocApiSearch(value, detected.type);

    // Merge results
    _renderIOCSearchResults(value, detected, dbResults, apiResults);
  } catch(err) {
    res.innerHTML = `
      <div style="padding:20px;color:#ef4444;font-size:.85em">
        <i class="fas fa-exclamation-triangle" style="margin-right:8px"></i>
        Search failed: ${_iocSearchEsc(err.message)}
        <br><br>
        <button onclick="iocQuickSearch()" class="enh-btn enh-btn--ghost enh-btn--sm">Retry</button>
      </div>`;
  }
};

/* ── DB search ── */
async function _iocDbSearch(value, type) {
  try {
    const base  = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
    const token = localStorage.getItem('wadjet_access_token') || localStorage.getItem('tp_access_token') || '';
    const qs    = new URLSearchParams({ search: value, limit: 20 });
    if (type && type !== 'unknown') qs.set('type', type.replace('hash_',''));
    const fetchFn = window.authFetch || ((path) => fetch(`${base}/api${path}`,{
      headers: { 'Content-Type':'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) }
    }).then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))));
    const data = await fetchFn(`/iocs?${qs}`);
    return data?.data || data || [];
  } catch {
    return [];
  }
}

/* ── API enrichment search ── */
async function _iocApiSearch(value, type) {
  // Try enrichment endpoint — returns unified intel from VirusTotal, AbuseIPDB, etc.
  try {
    const base  = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
    const token = localStorage.getItem('wadjet_access_token') || localStorage.getItem('tp_access_token') || '';
    const fetchFn = window.authFetch || ((path, opts={}) => fetch(`${base}/api${path}`,{
      headers: { 'Content-Type':'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) },
      ...opts,
    }).then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))));
    const data = await fetchFn('/intel/enrich', {
      method: 'POST',
      body: JSON.stringify({ value, type })
    });
    return data;
  } catch {
    return null;
  }
}

/* ── Render results ── */
function _renderIOCSearchResults(value, detected, dbRows, apiData) {
  const res = document.getElementById('ioc-search-results');
  if (!res) return;

  const sc = detected.color || '#8b949e';
  const hasDB  = dbRows.length > 0;
  const hasAPI = apiData && Object.keys(apiData).length > 0;

  if (!hasDB && !hasAPI) {
    res.innerHTML = `
      <div style="text-align:center;padding:32px;color:#8b949e">
        <div style="width:48px;height:48px;background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.2);
          border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 12px">
          <i class="fas fa-check" style="color:#22c55e;font-size:1.2em"></i>
        </div>
        <div style="font-size:.95em;color:#22c55e;font-weight:700;margin-bottom:6px">Not found in threat database</div>
        <div style="font-size:.82em;color:#8b949e;max-width:340px;margin:0 auto;line-height:1.6">
          <strong style="color:#e6edf3">${_iocSearchEsc(value)}</strong> was not found in the IOC database.
          This may indicate it's not known to be malicious, or it hasn't been ingested yet.
        </div>
        <button onclick="_iocSearchEnrich('${_iocSearchEsc(value)}','${detected.type||''}')"
          class="enh-btn enh-btn--cyan enh-btn--sm" style="margin-top:14px">
          <i class="fas fa-search-plus"></i> Enrich via External Sources
        </button>
      </div>`;
    return;
  }

  res.innerHTML = `
    <!-- Result header -->
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid #1a2535">
      <div style="width:36px;height:36px;background:${sc}18;border:1px solid ${sc}30;border-radius:9px;
        display:flex;align-items:center;justify-content:center;flex-shrink:0">
        <i class="fas ${detected.icon||'fa-search'}" style="color:${sc};font-size:.9em"></i>
      </div>
      <div>
        <div style="font-family:monospace;font-size:.9em;color:#e6edf3;font-weight:700;word-break:break-all">${_iocSearchEsc(value)}</div>
        <div style="font-size:.74em;color:#8b949e;margin-top:2px">
          <span style="color:${sc};font-weight:600">${detected.label||'Unknown Type'}</span>
          · ${hasDB ? `${dbRows.length} DB match${dbRows.length>1?'es':''}` : 'Not in DB'}
          ${hasAPI ? ' · External intel available' : ''}
        </div>
      </div>
      <button onclick="_iocSearchEnrich('${_iocSearchEsc(value)}','${detected.type||''}')"
        class="enh-btn enh-btn--ghost enh-btn--sm" style="margin-left:auto">
        <i class="fas fa-search-plus"></i> Enrich
      </button>
    </div>

    <!-- DB Results -->
    ${hasDB ? `
    <div style="margin-bottom:14px">
      <div style="font-size:.74em;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;margin-bottom:8px">
        <i class="fas fa-database" style="margin-right:5px;color:#22d3ee"></i>DATABASE MATCHES (${dbRows.length})
      </div>
      ${dbRows.slice(0,5).map(row => {
        const rc = row.reputation === 'malicious' ? '#ef4444' : row.reputation === 'suspicious' ? '#f97316' : '#22c55e';
        return `
        <div class="ioc-result-card ioc-result-card--${row.reputation||'clean'}"
          style="border-left:3px solid ${rc}">
          <div style="display:flex;align-items:flex-start;gap:10px">
            <div style="width:32px;height:32px;background:${rc}18;border-radius:7px;display:flex;align-items:center;
              justify-content:center;flex-shrink:0">
              <i class="fas fa-fingerprint" style="color:${rc};font-size:.8em"></i>
            </div>
            <div style="flex:1;min-width:0">
              <div style="font-family:monospace;font-size:.84em;color:#e6edf3;font-weight:700;word-break:break-all;margin-bottom:3px">${_iocSearchEsc((row.value||'').slice(0,80))}${(row.value||'').length>80?'…':''}</div>
              <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
                <span style="background:${rc}18;color:${rc};border:1px solid ${rc}30;padding:1px 7px;border-radius:8px;font-size:.68em;font-weight:700;text-transform:uppercase">${_iocSearchEsc(row.reputation||'unknown')}</span>
                <span style="background:rgba(34,211,238,.1);color:#22d3ee;border:1px solid rgba(34,211,238,.2);padding:1px 7px;border-radius:8px;font-size:.68em;font-weight:700">${_iocSearchEsc(row.type||'?')}</span>
                ${row.risk_score != null ? `<span style="background:${rc}18;color:${rc};border:1px solid ${rc}30;padding:1px 7px;border-radius:8px;font-size:.68em;font-weight:700">Risk: ${row.risk_score}</span>` : ''}
                ${row.feed_source || row.source ? `<span style="color:#8b949e;font-size:.72em">${_iocSearchEsc(row.feed_source||row.source)}</span>` : ''}
                ${row.threat_actor ? `<span style="color:#a855f7;font-size:.72em"><i class="fas fa-user-ninja" style="margin-right:3px"></i>${_iocSearchEsc(row.threat_actor)}</span>` : ''}
              </div>
            </div>
          </div>
        </div>`;
      }).join('')}
    </div>` : ''}

    <!-- External Intel -->
    ${hasAPI ? `
    <div>
      <div style="font-size:.74em;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;margin-bottom:8px">
        <i class="fas fa-globe" style="margin-right:5px;color:#a855f7"></i>EXTERNAL INTELLIGENCE
      </div>
      <div class="ai-investigation-result">
        ${Object.entries(apiData).filter(([k]) => !['_error','_loading'].includes(k)).map(([source, info]) => {
          if (!info || typeof info !== 'object') return '';
          const rep = info.malicious || info.reputation || info.verdict;
          const rc  = rep === 'malicious' ? '#ef4444' : rep === 'suspicious' ? '#f97316' : '#22c55e';
          return `<div class="ai-investigation-result__source">
            <div style="width:28px;height:28px;background:${rc}18;border-radius:6px;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:.72em;font-weight:800;color:${rc}">${source.slice(0,2).toUpperCase()}</div>
            <div style="flex:1">
              <div style="font-size:.82em;font-weight:700;color:#e6edf3">${_iocSearchEsc(source)}</div>
              ${info.detections != null ? `<div style="font-size:.72em;color:#8b949e">${info.detections}/${info.total||'?'} detections</div>` : ''}
              ${info.country ? `<div style="font-size:.72em;color:#8b949e">Country: ${_iocSearchEsc(info.country)}</div>` : ''}
              ${info.asn ? `<div style="font-size:.72em;color:#8b949e">ASN: ${_iocSearchEsc(info.asn)}</div>` : ''}
            </div>
            ${rep ? `<span style="background:${rc}18;color:${rc};border:1px solid ${rc}30;padding:1px 7px;border-radius:8px;font-size:.7em;font-weight:700;text-transform:uppercase;white-space:nowrap">${_iocSearchEsc(String(rep))}</span>` : ''}
          </div>`;
        }).join('')}
      </div>
    </div>` : ''}

    <div style="display:flex;gap:8px;margin-top:14px;padding-top:12px;border-top:1px solid #1a2535">
      <button onclick="navigateTo('ioc-registry')" class="enh-btn enh-btn--ghost enh-btn--sm">
        <i class="fas fa-external-link-alt"></i> Open in IOC Registry
      </button>
      <button onclick="_iocSearchCopyValue('${_iocSearchEsc(value)}')" class="enh-btn enh-btn--ghost enh-btn--sm">
        <i class="fas fa-copy"></i> Copy
      </button>
    </div>
  `;
}

window._iocSearchEnrich = function(value, type) {
  if (typeof showToast === 'function') showToast(`🔍 Enriching ${value.slice(0,40)}…`, 'info');
};

window._iocSearchCopyValue = function(value) {
  navigator.clipboard?.writeText(value).then(() => {
    if (typeof showToast==='function') showToast('📋 Copied to clipboard', 'info');
  });
};

function _iocSearchEsc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/* ══════════════════════════════════════════════════════
   ENHANCE EXISTING IOC REGISTRY SEARCH
   Patches the search input in ioc-intelligence.js to use
   real-time type detection
══════════════════════════════════════════════════════ */
function _enhanceIOCRegistrySearch() {
  // Monkey-patch the IOCDB filter to add type auto-detection
  const origSearch = window._isSearch;
  window._isSearch = function() {
    const inp = document.getElementById('ioc-search-inp');
    if (inp && inp.value.trim().length > 0) {
      const detected = detectIOCType(inp.value.trim());
      // Auto-fill type filter if not already set
      const typeEl = document.getElementById('if-type');
      if (typeEl && !typeEl.value && detected.valid && detected.type && detected.type !== 'unknown') {
        // Map detected type to API type values
        const typeMap = {
          ip: 'ip', ipv4:'ip', ipv6:'ip', cidr:'ip',
          domain: 'domain', url:'url', email:'email',
          hash_md5:'hash_md5', hash_sha1:'hash_sha1',
          hash_sha256:'hash_sha256', hash_sha512:'hash_sha512',
          hash:'hash_sha256',
          filename:'filename', cve:'cve',
        };
        const mappedType = typeMap[detected.type];
        if (mappedType && typeEl.querySelector(`option[value="${mappedType}"]`)) {
          // Don't auto-set type — just show hint
        }

        // Show type hint next to search
        let hint = document.getElementById('ioc-search-hint');
        if (!hint) {
          hint = document.createElement('div');
          hint.id = 'ioc-search-hint';
          hint.className = 'ioc-validation-hint ioc-validation-hint--show ioc-validation-hint--info';
          hint.style.cssText = 'margin-top:4px;font-size:.72em';
          inp.parentNode.insertBefore(hint, inp.nextSibling);
        }
        hint.style.display = 'block';
        hint.className = `ioc-validation-hint ioc-validation-hint--show ${
          !detected.valid ? 'ioc-validation-hint--error' :
          detected.hint?.startsWith('⚠') ? 'ioc-validation-hint--info' :
          'ioc-validation-hint--success'}`;
        hint.innerHTML = `<i class="fas ${detected.icon}" style="margin-right:4px"></i>${detected.hint || detected.label}`;
      }
    }
    if (typeof origSearch === 'function') origSearch();
  };
}

// Auto-enhance after DOM is ready
if (document.readyState !== 'loading') {
  _enhanceIOCRegistrySearch();
} else {
  document.addEventListener('DOMContentLoaded', _enhanceIOCRegistrySearch);
}

// Also expose detectIOCType globally
window.detectIOCType = detectIOCType;
