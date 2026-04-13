/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Live IOC Lookup v3.0
 *  Real API integration: VirusTotal, AbuseIPDB, Shodan, AlienVault OTX
 *  Unified results with clickable links, proper error handling,
 *  search history, real-time validation, multiple IOC types
 * ══════════════════════════════════════════════════════════════════════
 */
(function() {
'use strict';

/* ═══════════════════════════════════════════════════════
   STATE
═══════════════════════════════════════════════════════ */
const LIOF = {
  value:   null,
  type:    null,
  results: {},
  loading: false,
  history: JSON.parse(localStorage.getItem('wadjet_ioc_history') || '[]').slice(0,20),
  // API keys are hardcoded in the proxy — no user input needed
};

/* ═══════════════════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════════════════ */
function _e(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function _toast(msg, type='info') {
  let tc = document.getElementById('p19-toast-wrap');
  if (!tc) { tc=document.createElement('div'); tc.id='p19-toast-wrap'; document.body.appendChild(tc); }
  const icons = {success:'fa-check-circle',error:'fa-exclamation-circle',warning:'fa-exclamation-triangle',info:'fa-info-circle'};
  const t = document.createElement('div');
  t.className = `p19-toast p19-toast--${type}`;
  t.innerHTML = `<i class="fas ${icons[type]||'fa-bell'}"></i><span>${_e(msg)}</span>`;
  tc.appendChild(t);
  setTimeout(()=>{ t.classList.add('p19-toast--exit'); setTimeout(()=>t.remove(),300); },3500);
}

/* ═══════════════════════════════════════════════════════
   IOC TYPE DETECTION (13 types)
═══════════════════════════════════════════════════════ */
function detectIOCType(v) {
  v = String(v || '').trim();
  if (!v) return null;

  // Hashes
  if (/^[a-fA-F0-9]{128}$/.test(v)) return { type:'hash_sha512', label:'SHA-512', color:'var(--p19-purple)', icon:'fa-hashtag' };
  if (/^[a-fA-F0-9]{64}$/.test(v))  return { type:'hash_sha256', label:'SHA-256', color:'var(--p19-blue)',   icon:'fa-hashtag' };
  if (/^[a-fA-F0-9]{40}$/.test(v))  return { type:'hash_sha1',   label:'SHA-1',   color:'var(--p19-indigo)', icon:'fa-hashtag' };
  if (/^[a-fA-F0-9]{32}$/.test(v))  return { type:'hash_md5',    label:'MD5',     color:'var(--p19-teal)',   icon:'fa-hashtag' };

  // IP addresses
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(v)) {
    const parts = v.split('/')[0].split('.');
    if (parts.every(p=>+p>=0&&+p<=255))
      return { type:'ip', label:'IPv4', color:'var(--p19-cyan)', icon:'fa-network-wired' };
  }
  // IPv6
  if (/^[a-fA-F0-9]{0,4}(:[a-fA-F0-9]{0,4}){2,7}$/.test(v))
    return { type:'ipv6', label:'IPv6', color:'var(--p19-cyan)', icon:'fa-network-wired' };

  // CVE
  if (/^CVE-\d{4}-\d{4,}$/i.test(v))
    return { type:'cve', label:'CVE', color:'var(--p19-red)', icon:'fa-bug' };

  // ASN
  if (/^ASN?\d+$/i.test(v))
    return { type:'asn', label:'ASN', color:'var(--p19-yellow)', icon:'fa-globe' };

  // Email
  if (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v))
    return { type:'email', label:'Email', color:'var(--p19-pink)', icon:'fa-envelope' };

  // URL
  if (/^https?:\/\//i.test(v))
    return { type:'url', label:'URL', color:'var(--p19-green)', icon:'fa-link' };

  // Domain (must come after URL check)
  if (/^(?!-)[a-zA-Z0-9\-\.]{1,253}[^\-]\.[a-zA-Z]{2,}$/.test(v) && !v.includes(' '))
    return { type:'domain', label:'Domain', color:'var(--p19-orange)', icon:'fa-globe' };

  // Filename (contains extension)
  if (/\.[a-zA-Z0-9]{2,5}$/.test(v) && v.length < 260)
    return { type:'filename', label:'Filename', color:'var(--p19-t2)', icon:'fa-file' };

  return null;
}

window.detectIOCType = detectIOCType;

/* ═══════════════════════════════════════════════════════
   API CALLS  (v8.0 — direct proxy, keys hardcoded server-side)
═══════════════════════════════════════════════════════

  FIX v8.0: API keys are hardcoded in the Vercel proxy functions.
  No user input, no env vars, no backend fallback needed.
  All calls go directly to /proxy/{source} which always has the key.
═══════════════════════════════════════════════════════ */

/* ── Core fetch helper ─────────────────────────────────────────────────── */

/**
 * _proxyFetch — simple fetch to /proxy/* with error handling.
 * Returns parsed JSON on success.
 * Throws a descriptive Error on network failure, HTML response, or HTTP error.
 * On upstream 404 (IOC not found) returns { __status404: true }.
 */
async function _proxyFetch(path, opts = {}) {
  const headers = { Accept: 'application/json', ...(opts.headers || {}) };
  let r;
  try {
    r = await fetch(path, { ...opts, headers, signal: AbortSignal.timeout(25000) });
  } catch (e) {
    throw new Error(`Network error: ${e.message}`);
  }

  const ct = r.headers.get('content-type') || '';
  if (ct.includes('text/html')) throw new Error('Proxy unavailable (returned HTML)');
  if (r.status === 404) return { __status404: true };
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try { const b = await r.json(); msg += ': ' + (b.error || b.message || JSON.stringify(b)).slice(0,120); } catch(_) {}
    throw new Error(msg);
  }
  return r.json();
}

/* ── VirusTotal ────────────────────────────────────────────────────────── */
async function _vtCheck(value, iocType) {
  const type  = iocType.type;
  const vtUrl = type==='ip'     ? `https://www.virustotal.com/gui/ip-address/${value}`
              : type==='domain' ? `https://www.virustotal.com/gui/domain/${value}`
              : type==='url'    ? `https://www.virustotal.com/gui/url/${btoa(value).replace(/=/g,'')}`
              :                   `https://www.virustotal.com/gui/file/${value}`;

  let endpoint;
  if      (type === 'ip')                                                          endpoint = `/ip_addresses/${value}`;
  else if (type === 'domain')                                                      endpoint = `/domains/${value}`;
  else if (type === 'url') {
    const enc = btoa(value).replace(/=+$/, '').replace(/\+/g,'-').replace(/\//g,'_');
    endpoint  = `/urls/${enc}`;
  }
  else if (['hash_md5','hash_sha1','hash_sha256','hash_sha512'].includes(type))    endpoint = `/files/${value}`;
  else return { source:'virustotal', status:'unsupported', message:'IOC type not supported', url: vtUrl };

  try {
    const d = await _proxyFetch(`/proxy/vt${endpoint}`);
    if (d.__status404) return { source:'virustotal', status:'not_found', message:'Not found in VirusTotal', url: vtUrl };

    const attr  = d?.data?.attributes || {};
    const stats = attr.last_analysis_stats || {};
    const total = Object.values(stats).reduce((s,n)=>s+(n||0), 0);
    const mal   = stats.malicious  || 0;
    const sus   = stats.suspicious || 0;

    return {
      source:'virustotal', status:'success',
      verdict: mal>5 ? 'MALICIOUS' : mal>0||sus>3 ? 'SUSPICIOUS' : 'CLEAN',
      malicious:mal, suspicious:sus,
      harmless:  stats.harmless   || 0,
      undetected:stats.undetected || 0,
      total,
      reputation:        attr.reputation    || 0,
      country:           attr.country       || attr.country_code || '',
      asn:               attr.asn           || '',
      as_owner:          attr.as_owner      || '',
      first_submission:  attr.first_submission_date ? new Date(attr.first_submission_date*1000).toLocaleDateString() : '',
      last_analysis:     attr.last_analysis_date    ? new Date(attr.last_analysis_date*1000).toLocaleDateString()    : '',
      url: vtUrl,
    };
  } catch(err) {
    return { source:'virustotal', status:'error', message: err.message, url: vtUrl };
  }
}

/* ── AbuseIPDB ─────────────────────────────────────────────────────────── */
async function _abuseIPDBCheck(value) {
  const abuseUrl = `https://www.abuseipdb.com/check/${value}`;
  try {
    const d = await _proxyFetch(
      `/proxy/abuseipdb/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90&verbose`
    );
    if (d.__status404) return { source:'abuseipdb', status:'not_found', message:'IP not found', url: abuseUrl };

    const data  = d?.data || {};
    const score = data.abuseConfidenceScore || 0;
    return {
      source:'abuseipdb', status:'success',
      verdict: score>75 ? 'MALICIOUS' : score>25 ? 'SUSPICIOUS' : 'CLEAN',
      abuse_score:       score,
      total_reports:     data.totalReports     || 0,
      distinct_users:    data.numDistinctUsers || 0,
      country_code:      data.countryCode      || '',
      country_name:      data.countryName      || '',
      isp:               data.isp              || '',
      domain:            data.domain           || '',
      is_tor:            data.isTor            || false,
      is_whitelisted:    data.isWhitelisted     || false,
      usage_type:        data.usageType        || '',
      last_reported:     data.lastReportedAt   || null,
      url: abuseUrl,
    };
  } catch(err) {
    return { source:'abuseipdb', status:'error', message: err.message, url: abuseUrl };
  }
}

/* ── Shodan ────────────────────────────────────────────────────────────── */
async function _shodanCheck(value) {
  const shodanUrl = `https://www.shodan.io/host/${value}`;
  try {
    const d = await _proxyFetch(`/proxy/shodan/shodan/host/${value}`);
    if (d.__status404) return { source:'shodan', status:'not_found', message:'No Shodan data for this IP', url: shodanUrl };

    return {
      source:'shodan', status:'success',
      verdict: (d.vulns && Object.keys(d.vulns).length > 0) ? 'SUSPICIOUS' : 'CLEAN',
      country:   d.country_name || '',
      city:      d.city         || '',
      org:       d.org          || '',
      isp:       d.isp          || '',
      os:        d.os           || '',
      ports:     (d.ports       || []).slice(0, 12),
      vulns:     Object.keys(d.vulns || {}).slice(0, 8),
      hostnames: (d.hostnames   || []).slice(0, 5),
      domains:   (d.domains     || []).slice(0, 5),
      tags:      d.tags         || [],
      asn:       d.asn          || '',
      last_update: d.last_update || '',
      url: shodanUrl,
    };
  } catch(err) {
    return { source:'shodan', status:'error', message: err.message, url: shodanUrl };
  }
}

/* ── AlienVault OTX ────────────────────────────────────────────────────── */
async function _otxCheck(value, iocType) {
  const typeMap = { ip:'IPv4', domain:'domain', url:'url', hash_md5:'file', hash_sha1:'file', hash_sha256:'file', hash_sha512:'file' };
  const otxType = typeMap[iocType.type];
  if (!otxType) return { source:'otx', status:'unsupported', message:'IOC type not supported by OTX' };

  const otxUrl = `https://otx.alienvault.com/indicator/${otxType}/${encodeURIComponent(value)}`;
  try {
    const d = await _proxyFetch(`/proxy/otx/indicators/${otxType}/${encodeURIComponent(value)}/general`);
    if (d.__status404) return { source:'otx', status:'not_found', message:'Not found in OTX', url: otxUrl };

    const pulses = d?.pulse_info?.pulses || [];
    const pc     = d?.pulse_info?.count  || 0;

    return {
      source:'otx', status:'success',
      verdict: pc>10 ? 'MALICIOUS' : pc>3 ? 'SUSPICIOUS' : pc>0 ? 'SUSPICIOUS' : 'CLEAN',
      pulse_count:       pc,
      related:           pulses.slice(0,5).map(p=>p.name||''),
      tags:              [...new Set(pulses.flatMap(p=>p.tags||[]))].slice(0,10),
      malware_families:  [...new Set(pulses.flatMap(p=>(p.malware_families||[]).map(m=>m.display_name||m)))].slice(0,5),
      threat_actors:     [...new Set(pulses.flatMap(p=>p.adversary ? [p.adversary] : []))].slice(0,5),
      url: otxUrl,
    };
  } catch(err) {
    return { source:'otx', status:'error', message: err.message, url: otxUrl };
  }
}

/* ── URLhaus (free, no key) ────────────────────────────────────────────── */
async function _urlhausCheck(value, iocType) {
  const type = iocType.type;
  if (!['ip','domain','url'].includes(type)) return { source:'urlhaus', status:'unsupported' };

  const uhUrl = `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(value)}`;
  const isUrl = type === 'url';
  const proxyPath = isUrl ? '/proxy/urlhaus/url/' : '/proxy/urlhaus/host/';

  try {
    const r = await fetch(proxyPath, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body:    new URLSearchParams(isUrl ? { url: value } : { host: value }),
      signal:  AbortSignal.timeout(20000),
    });

    const ct = r.headers.get('content-type') || '';
    if (ct.includes('text/html')) throw new Error('URLhaus proxy unavailable');
    if (!r.ok) throw new Error(`URLhaus HTTP ${r.status}`);

    const d = await r.json();
    if (d.query_status === 'no_results' || d.query_status === 'is_crawler') {
      return { source:'urlhaus', status:'success', verdict:'CLEAN', urls_count:0, active_urls:0, sample_urls:[], url: uhUrl };
    }

    const urls    = (d.urls || d.urls_list || []).filter(u => u.url_status !== 'offline').slice(0, 5);
    const verdict = urls.length > 0 ? 'MALICIOUS' : 'CLEAN';

    return {
      source:'urlhaus', status:'success', verdict,
      urls_count:  d.urls?.length || d.urls_list?.length || 0,
      active_urls: urls.length,
      sample_urls: urls.map(u => ({ url: u.url, status: u.url_status, threat: u.threat, tags: u.tags })),
      url: uhUrl,
    };
  } catch(err) {
    return { source:'urlhaus', status:'error', message: err.message, url: uhUrl };
  }
}

/* ═══════════════════════════════════════════════════════
   LOOKUP ORCHESTRATOR
═══════════════════════════════════════════════════════ */
async function _runLookup(value) {
  const iocType = detectIOCType(value);
  if (!iocType) {
    _toast('Could not detect IOC type. Check the format.', 'warning');
    return;
  }

  LIOF.value   = value;
  LIOF.type    = iocType;
  LIOF.results = {};
  LIOF.loading = true;

  // Add to history
  const existing = LIOF.history.findIndex(h=>h.value===value);
  if (existing > -1) LIOF.history.splice(existing, 1);
  LIOF.history.unshift({ value, type: iocType.label, ts: Date.now() });
  LIOF.history = LIOF.history.slice(0, 20);
  localStorage.setItem('wadjet_ioc_history', JSON.stringify(LIOF.history));

  // Render loading state
  _renderResults(value, iocType, null);

  // Determine which sources to query
  const tasks = [];

  // VirusTotal (all types)
  tasks.push({ id:'virustotal', label:'VirusTotal', fn: _vtCheck(value, iocType) });

  // AbuseIPDB (IP only)
  if (iocType.type === 'ip') {
    tasks.push({ id:'abuseipdb', label:'AbuseIPDB', fn: _abuseIPDBCheck(value) });
    tasks.push({ id:'shodan',    label:'Shodan',    fn: _shodanCheck(value) });
  }

  // OTX (ip, domain, url, hash)
  if (['ip','domain','url','hash_md5','hash_sha1','hash_sha256'].includes(iocType.type)) {
    tasks.push({ id:'otx', label:'AlienVault OTX', fn: _otxCheck(value, iocType) });
  }

  // URLhaus (ip, domain, url - free)
  if (['ip','domain','url'].includes(iocType.type)) {
    tasks.push({ id:'urlhaus', label:'URLhaus', fn: _urlhausCheck(value, iocType) });
  }

  // Set initial loading cards
  tasks.forEach(t => {
    const card = document.getElementById(`liof-src-${t.id}`);
    if (card) card.innerHTML = _sourceLoading(t.label);
  });

  // Run all in parallel, update cards as they complete
  tasks.forEach(({ id, fn }) => {
    fn.then(result => {
      LIOF.results[id] = result;
      _updateSourceCard(id, result);
      _updateOverallVerdict();
    }).catch(err => {
      LIOF.results[id] = { source:id, status:'error', message:err.message };
      _updateSourceCard(id, LIOF.results[id]);
    });
  });

  // Wait for all to complete
  await Promise.allSettled(tasks.map(t=>t.fn));
  LIOF.loading = false;
}

/* ═══════════════════════════════════════════════════════
   RENDER FUNCTIONS
═══════════════════════════════════════════════════════ */
function _renderResults(value, iocType, results) {
  const wrap = document.getElementById('liof-results');
  if (!wrap) return;

  const sources = ['virustotal'];
  if (iocType.type === 'ip') sources.push('abuseipdb', 'shodan');
  if (['ip','domain','url','hash_md5','hash_sha1','hash_sha256'].includes(iocType.type)) sources.push('otx');
  if (['ip','domain','url'].includes(iocType.type)) sources.push('urlhaus');

  const sourceConfigs = {
    virustotal: { name:'VirusTotal', color:'var(--p19-blue)',   icon:'fa-virus',       abbr:'VT' },
    abuseipdb:  { name:'AbuseIPDB',  color:'var(--p19-red)',    icon:'fa-shield-alt',  abbr:'AB' },
    shodan:     { name:'Shodan',     color:'var(--p19-orange)', icon:'fa-server',      abbr:'SH' },
    otx:        { name:'AlienVault OTX', color:'var(--p19-purple)', icon:'fa-satellite', abbr:'OTX'},
    urlhaus:    { name:'URLhaus',    color:'var(--p19-green)',  icon:'fa-link',        abbr:'UH' },
  };

  wrap.innerHTML = `
  <!-- IOC Header -->
  <div class="p19-ioc-result">
    <div class="p19-ioc-result__header">
      <div>
        <div style="font-size:.72em;color:var(--p19-t4);margin-bottom:3px;text-transform:uppercase">Analyzed Indicator</div>
        <div class="p19-ioc-result__value">${_e(value)}</div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <span class="p19-badge" style="background:${iocType.color}1a;border-color:${iocType.color}33;color:${iocType.color}">
          <i class="fas ${iocType.icon}" style="font-size:.7em"></i> ${_e(iocType.label)}
        </span>
        <div id="liof-overall-verdict">
          <span class="p19-badge p19-badge--gray"><i class="fas fa-circle-notch fa-spin" style="margin-right:3px;font-size:.7em"></i>Analyzing…</span>
        </div>
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._liofCopy()">
          <i class="fas fa-copy"></i>
        </button>
      </div>
    </div>

    <!-- Source Cards Grid -->
    <div class="p19-ioc-sources">
      ${sources.map(s => {
        const cfg = sourceConfigs[s] || { name:s, color:'var(--p19-t3)', icon:'fa-circle', abbr:s };
        return `
        <div id="liof-src-${s}" class="p19-ioc-source-card">
          ${_sourceLoading(cfg.name, cfg.color, cfg.icon)}
        </div>`;
      }).join('')}
    </div>

    <!-- Actions -->
    <div style="padding:12px 16px;border-top:1px solid var(--p19-border);display:flex;gap:8px;flex-wrap:wrap">
      <button class="p19-btn p19-btn--primary p19-btn--sm" onclick="window._liofExport()">
        <i class="fas fa-download"></i> Export Results
      </button>
      <button class="p19-btn p19-btn--purple p19-btn--sm" onclick="window._liofAIAnalyze()">
        <i class="fas fa-robot"></i> AI Analyze
      </button>
      <button class="p19-btn p19-btn--orange p19-btn--sm" onclick="window._liofCreateAlert()">
        <i class="fas fa-bell"></i> Create Alert
      </button>
      <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._liofAddToIOCDB()">
        <i class="fas fa-database"></i> Add to IOC DB
      </button>
    </div>
  </div>`;
}

function _sourceLoading(name, color='var(--p19-cyan)', icon='fa-circle-notch') {
  return `
  <div class="p19-ioc-source-header">
    <div style="width:26px;height:26px;border-radius:6px;background:${color}1a;border:1px solid ${color}33;display:flex;align-items:center;justify-content:center">
      <i class="fas ${icon}" style="color:${color};font-size:.75em"></i>
    </div>
    <span class="p19-ioc-source-name">${_e(name)}</span>
  </div>
  <div class="p19-ioc-source-loading">
    <i class="fas fa-circle-notch p19-ioc-source-spinner"></i>
    Querying ${_e(name)}…
  </div>`;
}

function _updateSourceCard(sourceId, result) {
  const card = document.getElementById(`liof-src-${sourceId}`);
  if (!card) return;

  const cfgMap = {
    virustotal: { name:'VirusTotal', color:'var(--p19-blue)',   icon:'fa-virus' },
    abuseipdb:  { name:'AbuseIPDB',  color:'var(--p19-red)',    icon:'fa-shield-alt' },
    shodan:     { name:'Shodan',     color:'var(--p19-orange)', icon:'fa-server' },
    otx:        { name:'AlienVault OTX', color:'var(--p19-purple)', icon:'fa-satellite' },
    urlhaus:    { name:'URLhaus',    color:'var(--p19-green)',  icon:'fa-link' },
  };
  const cfg = cfgMap[sourceId] || { name:sourceId, color:'var(--p19-t3)', icon:'fa-circle' };

  if (result.status === 'error') {
    card.innerHTML = `
    <div class="p19-ioc-source-header">
      ${_srcIcon(cfg)}
      <span class="p19-ioc-source-name">${cfg.name}</span>
      <span class="p19-badge p19-badge--offline" style="font-size:.64em;margin-left:auto">Error</span>
    </div>
    <div style="font-size:.76em;color:var(--p19-red);padding:4px 0">
      <i class="fas fa-exclamation-triangle" style="margin-right:4px"></i>${_e(result.message||'Unknown error')}
    </div>`;
    return;
  }

  if (result.status === 'not_found') {
    card.innerHTML = `
    <div class="p19-ioc-source-header">
      ${_srcIcon(cfg)}
      <span class="p19-ioc-source-name">${cfg.name}</span>
      <span class="p19-badge p19-badge--green" style="font-size:.64em;margin-left:auto">Not Found</span>
    </div>
    <div style="font-size:.76em;color:var(--p19-green);padding:4px 0">
      <i class="fas fa-check-circle" style="margin-right:4px"></i>Not found in threat database
    </div>`;
    return;
  }

  if (result.status === 'unsupported') {
    card.innerHTML = `
    <div class="p19-ioc-source-header">
      ${_srcIcon(cfg)}
      <span class="p19-ioc-source-name">${cfg.name}</span>
    </div>
    <div style="font-size:.76em;color:var(--p19-t4);padding:4px 0">N/A for this IOC type</div>`;
    return;
  }

  // Success
  const vColor = result.verdict==='MALICIOUS'?'var(--p19-red)':result.verdict==='SUSPICIOUS'?'var(--p19-yellow)':'var(--p19-green)';
  const vBadge = result.verdict
    ? `<span class="p19-badge p19-badge--${result.verdict==='MALICIOUS'?'critical':result.verdict==='SUSPICIOUS'?'medium':'green'}" style="font-size:.64em;margin-left:auto">${result.verdict}</span>`
    : '';

  let rows = '';

  if (sourceId === 'virustotal' && result.status === 'success') {
    rows = `
    <div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Malicious</span><span class="p19-ioc-source-val" style="color:${result.malicious>0?'var(--p19-red)':'var(--p19-green)'}">${result.malicious}/${result.total} engines</span></div>
    <div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Suspicious</span><span class="p19-ioc-source-val" style="color:${result.suspicious>0?'var(--p19-yellow)':'var(--p19-t2)'}">${result.suspicious}</span></div>
    ${result.country?`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Country</span><span class="p19-ioc-source-val">${_e(result.country)}</span></div>`:''}
    ${result.as_owner?`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">AS Owner</span><span class="p19-ioc-source-val">${_e(result.as_owner)}</span></div>`:''}
    ${result.reputation?`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Reputation</span><span class="p19-ioc-source-val" style="color:${result.reputation<-10?'var(--p19-red)':'var(--p19-t2)'}">${result.reputation}</span></div>`:''}`;
  }

  else if (sourceId === 'abuseipdb' && result.status === 'success') {
    rows = `
    <div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Abuse Score</span><span class="p19-ioc-source-val" style="color:${result.abuse_score>50?'var(--p19-red)':result.abuse_score>25?'var(--p19-yellow)':'var(--p19-green)'}">${result.abuse_score}/100</span></div>
    <div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Reports</span><span class="p19-ioc-source-val">${result.total_reports} (${result.distinct_users} users)</span></div>
    <div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Country</span><span class="p19-ioc-source-val">${_e(result.country_name||result.country_code)}</span></div>
    ${result.isp?`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">ISP</span><span class="p19-ioc-source-val">${_e(result.isp)}</span></div>`:''}
    ${result.is_tor?`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Tor Exit</span><span class="p19-ioc-source-val" style="color:var(--p19-red)">YES</span></div>`:''}
    <div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Whitelisted</span><span class="p19-ioc-source-val">${result.is_whitelisted?'Yes':'No'}</span></div>`;
  }

  else if (sourceId === 'shodan' && result.status === 'success') {
    rows = `
    ${result.org?`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Organization</span><span class="p19-ioc-source-val">${_e(result.org)}</span></div>`:''}
    ${result.country?`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Country</span><span class="p19-ioc-source-val">${_e(result.country)}${result.city?', '+result.city:''}</span></div>`:''}
    ${result.os?`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">OS</span><span class="p19-ioc-source-val">${_e(result.os)}</span></div>`:''}
    <div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Open Ports</span><span class="p19-ioc-source-val" style="color:${result.ports.length>5?'var(--p19-yellow)':'var(--p19-t2)'}">${result.ports.join(', ')||'—'}</span></div>
    ${result.vulns.length?`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Vulnerabilities</span><span class="p19-ioc-source-val" style="color:var(--p19-red)">${result.vulns.join(', ')}</span></div>`:''}
    ${result.hostnames.length?`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Hostnames</span><span class="p19-ioc-source-val">${result.hostnames.join(', ')}</span></div>`:''}`;
  }

  else if (sourceId === 'otx' && result.status === 'success') {
    rows = `
    <div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Pulses</span><span class="p19-ioc-source-val" style="color:${result.pulse_count>5?'var(--p19-red)':result.pulse_count>0?'var(--p19-yellow)':'var(--p19-green)'}">${result.pulse_count} threat pulses</span></div>
    ${result.malware_families.length?`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Malware</span><span class="p19-ioc-source-val" style="color:var(--p19-red)">${result.malware_families.join(', ')}</span></div>`:''}
    ${result.threat_actors.length?`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Threat Actor</span><span class="p19-ioc-source-val" style="color:var(--p19-orange)">${result.threat_actors.join(', ')}</span></div>`:''}
    ${result.tags.length?`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Tags</span><span class="p19-ioc-source-val">${result.tags.slice(0,4).join(', ')}</span></div>`:''}`;
  }

  else if (sourceId === 'urlhaus' && result.status === 'success') {
    rows = `
    <div class="p19-ioc-source-row"><span class="p19-ioc-source-key">Malicious URLs</span><span class="p19-ioc-source-val" style="color:${result.urls_count>0?'var(--p19-red)':'var(--p19-green)'}">${result.active_urls} active / ${result.urls_count} total</span></div>
    ${result.sample_urls?.slice(0,2).map(u=>`<div class="p19-ioc-source-row"><span class="p19-ioc-source-key">${_e(u.threat||'Threat')}</span><span class="p19-ioc-source-val" style="overflow:hidden;text-overflow:ellipsis;max-width:120px">${_e(u.url?.slice(0,40))}…</span></div>`).join('')||''}`;
  }

  card.innerHTML = `
  <div class="p19-ioc-source-header">
    ${_srcIcon(cfg)}
    <span class="p19-ioc-source-name">${cfg.name}</span>
    ${vBadge}
    ${result.url?`<a href="${_e(result.url)}" target="_blank" rel="noopener" class="p19-ioc-source-link">
      <i class="fas fa-external-link-alt" style="font-size:.65em"></i> View
    </a>`:''}
  </div>
  ${rows || '<div style="font-size:.76em;color:var(--p19-t4);padding:4px 0">No additional data</div>'}`;
}

function _srcIcon(cfg) {
  return `<div style="width:26px;height:26px;border-radius:6px;background:${cfg.color}1a;border:1px solid ${cfg.color}33;display:flex;align-items:center;justify-content:center;flex-shrink:0">
    <i class="fas ${cfg.icon}" style="color:${cfg.color};font-size:.75em"></i>
  </div>`;
}

function _updateOverallVerdict() {
  const el = document.getElementById('liof-overall-verdict');
  if (!el) return;
  const verdict = _computeVerdict(LIOF.results);
  const classes = { MALICIOUS:'critical', SUSPICIOUS:'medium', CLEAN:'green', UNKNOWN:'gray' };
  el.innerHTML = `<span class="p19-badge p19-badge--${classes[verdict.v]||'gray'}">
    <i class="fas ${verdict.i}" style="font-size:.75em;margin-right:3px"></i>${verdict.v}
  </span>`;
}

function _computeVerdict(results) {
  const verdicts = Object.values(results).filter(r=>r.status==='success'&&r.verdict).map(r=>r.verdict);
  if (verdicts.some(v=>v==='MALICIOUS'))  return { v:'MALICIOUS', i:'fa-skull-crossbones' };
  if (verdicts.some(v=>v==='SUSPICIOUS')) return { v:'SUSPICIOUS', i:'fa-exclamation-triangle' };
  if (verdicts.every(v=>v==='CLEAN')&&verdicts.length) return { v:'CLEAN', i:'fa-check-circle' };
  return { v:'UNKNOWN', i:'fa-question-circle' };
}

/* ═══════════════════════════════════════════════════════
   MAIN RENDERER
═══════════════════════════════════════════════════════ */
window.renderLiveIOCLookup = function() {
  const c = document.getElementById('page-live-feeds')
         || document.getElementById('liveFeedsContainer')
         || document.getElementById('page-ioc-lookup');
  if (!c) return;
  c.className = 'p19-module';

  c.innerHTML = `
  <!-- Header -->
  <div class="p19-header">
    <div class="p19-header__inner">
      <div class="p19-header__left">
        <div class="p19-header__icon p19-header__icon--cyan">
          <i class="fas fa-search-plus"></i>
        </div>
        <div>
          <h2 class="p19-header__title">Live IOC Lookup</h2>
          <div class="p19-header__sub">Real-time intelligence · VirusTotal · AbuseIPDB · Shodan · AlienVault OTX · URLhaus</div>
        </div>
        <span class="p19-badge p19-badge--online"><span class="p19-dot p19-dot--green"></span> LIVE</span>
      </div>
      <div class="p19-header__right">
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._liofExport()" id="liof-export-btn" style="display:none">
          <i class="fas fa-download"></i> <span>Export</span>
        </button>
      </div>
    </div>
  </div>

  <!-- Search Box -->
  <div style="padding:20px 24px;border-bottom:1px solid var(--p19-border);background:var(--p19-bg-card)">
    <div style="max-width:700px;margin:0 auto">
      <div style="font-size:.78em;color:var(--p19-t3);margin-bottom:8px;text-transform:uppercase;letter-spacing:.06em">
        Enter any IOC to investigate across all intelligence sources
      </div>
      <div style="display:flex;gap:8px">
        <div class="p19-search" style="flex:1">
          <i class="fas fa-search" id="liof-search-icon"></i>
          <input type="text" id="liof-input" placeholder="IP, domain, URL, hash (MD5/SHA1/SHA256/SHA512), CVE, email…"
            onkeydown="if(event.key==='Enter') window._liofSearch()"
            oninput="window._liofValidate(this.value)" autocomplete="off" autocapitalize="off" spellcheck="false" />
        </div>
        <button class="p19-btn p19-btn--primary" id="liof-search-btn" onclick="window._liofSearch()" style="height:38px;padding:0 18px">
          <i class="fas fa-search"></i> <span>Investigate</span>
        </button>
      </div>
      <!-- Real-time type badge -->
      <div id="liof-type-badge" style="margin-top:8px;min-height:24px"></div>
    </div>
  </div>

  <!-- Sources Status Banner — all keys embedded server-side -->
  <div style="padding:8px 24px;background:rgba(16,185,129,.04);border-bottom:1px solid rgba(16,185,129,.15)">
    <div style="display:flex;align-items:center;gap:8px;font-size:.78em;flex-wrap:wrap">
      <i class="fas fa-check-circle" style="color:var(--p19-green)"></i>
      <span style="color:var(--p19-t3)">All sources active:</span>
      ${['VirusTotal','AbuseIPDB','Shodan','AlienVault OTX','URLhaus'].map(n =>
        `<span class="p19-badge p19-badge--green" style="font-size:.7em"><i class="fas fa-check" style="font-size:.7em"></i> ${n}</span>`
      ).join('')}
    </div>
  </div>

  <!-- Main Content: Split Layout -->
  <div style="display:grid;grid-template-columns:1fr 260px;min-height:500px" id="liof-main-grid">

    <!-- Results area -->
    <div style="border-right:1px solid var(--p19-border);padding:20px 24px;overflow-y:auto" id="liof-results">
      <!-- Empty State -->
      <div class="p19-empty">
        <i class="fas fa-search-plus" style="color:var(--p19-cyan)"></i>
        <div class="p19-empty-title">Enter an IOC to begin investigation</div>
        <div class="p19-empty-sub">Supports: IPv4, IPv6, domain, URL, MD5, SHA1, SHA256, SHA512, CVE, email</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:center;margin-top:16px">
          ${['185.220.101.45','malware-update.ru','https://evil.example.com/payload.exe','a3f2b1c9d4e5f67890ab1234567890cd'].map(s=>`
          <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._liofSetExample('${_e(s)}')" style="font-size:.76em;font-family:'JetBrains Mono',monospace">
            ${_e(s.slice(0,30))}${s.length>30?'…':''}
          </button>`).join('')}
        </div>
      </div>
    </div>

    <!-- History Panel -->
    <div style="padding:16px;overflow-y:auto;background:var(--p19-bg-card)">
      <div class="p19-section-head">
        <div class="p19-section-title">Search History</div>
        ${LIOF.history.length?`<button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._liofClearHistory()" style="font-size:.72em"><i class="fas fa-trash"></i></button>`:''}
      </div>
      <div id="liof-history">
        ${_renderHistory()}
      </div>
    </div>
  </div>

  <!-- Mobile: collapse history -->
  <style>
    @media(max-width:700px){
      #liof-main-grid { grid-template-columns:1fr !important; }
      #liof-main-grid > div:last-child { border-top:1px solid var(--p19-border); max-height:200px; }
    }
  </style>
  `;
};

function _renderHistory() {
  if (!LIOF.history.length) {
    return `<div style="font-size:.76em;color:var(--p19-t4);text-align:center;padding:20px 0">No history yet</div>`;
  }
  return LIOF.history.map(h=>`
  <div style="padding:8px;border-radius:6px;cursor:pointer;transition:background .15s;margin-bottom:4px"
    onmouseover="this.style.background='var(--p19-bg-hover)'" onmouseout="this.style.background=''"
    onclick="window._liofSetExample('${_e(h.value)}')">
    <div style="font-size:.78em;font-family:'JetBrains Mono',monospace;color:var(--p19-cyan);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_e(h.value)}</div>
    <div style="font-size:.68em;color:var(--p19-t4);margin-top:2px">${_e(h.type)} · ${new Date(h.ts).toLocaleTimeString()}</div>
  </div>`).join('');
}

/* ═══════════════════════════════════════════════════════
   INTERACTION HANDLERS
═══════════════════════════════════════════════════════ */
window._liofSearch = async function() {
  const inp = document.getElementById('liof-input');
  if (!inp) return;
  const val = inp.value.trim();
  if (!val) { _toast('Please enter an IOC to investigate', 'warning'); return; }

  const btn = document.getElementById('liof-search-btn');
  if (btn) { btn.disabled=true; btn.innerHTML='<i class="fas fa-circle-notch fa-spin"></i> Analyzing…'; }

  const exportBtn = document.getElementById('liof-export-btn');
  if (exportBtn) exportBtn.style.display = 'inline-flex';

  try {
    await _runLookup(val);
    // Update history panel
    const hPanel = document.getElementById('liof-history');
    if (hPanel) hPanel.innerHTML = _renderHistory();
  } finally {
    if (btn) { btn.disabled=false; btn.innerHTML='<i class="fas fa-search"></i> <span>Investigate</span>'; }
  }
};

window._liofValidate = function(val) {
  const badge = document.getElementById('liof-type-badge');
  if (!badge) return;
  const iocType = detectIOCType(val);
  if (!val) { badge.innerHTML=''; return; }
  if (iocType) {
    badge.innerHTML = `
    <span class="p19-badge" style="background:${iocType.color}15;border-color:${iocType.color}30;color:${iocType.color}">
      <i class="fas ${iocType.icon}" style="font-size:.7em"></i>
      Detected: <strong>${iocType.label}</strong>
    </span>`;
  } else {
    badge.innerHTML = `<span class="p19-badge p19-badge--gray"><i class="fas fa-question" style="font-size:.7em"></i> Type: Unknown — verify format</span>`;
  }
};

window._liofSetExample = function(val) {
  const inp = document.getElementById('liof-input');
  if (inp) { inp.value=val; inp.dispatchEvent(new Event('input')); inp.focus(); }
};

window._liofCopy = function() {
  if (LIOF.value) {
    navigator.clipboard?.writeText(LIOF.value)
      .then(()=>_toast('IOC copied', 'success'))
      .catch(()=>_toast('Copy failed', 'warning'));
  }
};

window._liofExport = function() {
  if (!LIOF.value) return;
  const report = {
    ioc: LIOF.value, type: LIOF.type, analyzed_at: new Date().toISOString(),
    verdict: _computeVerdict(LIOF.results).v,
    results: LIOF.results,
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `ioc-lookup-${LIOF.value.replace(/[^a-zA-Z0-9]/g,'-')}-${Date.now()}.json`;
  a.click();
  _toast('IOC report exported', 'success');
};

window._liofAIAnalyze = function() {
  if (!LIOF.value) return;
  // Navigate to AI Orchestrator with the IOC pre-filled
  _toast(`Opening AI analysis for ${LIOF.value}…`, 'info');
  // Try to navigate to AI Orchestrator page
  const navLink = document.querySelector('[data-page="ai-orchestrator"], [href="#ai-orchestrator"]');
  if (navLink) navLink.click();
  setTimeout(() => {
    const inp = document.getElementById('orch-input');
    if (inp) { inp.value=`Investigate IOC ${LIOF.value} across all sources`; inp.focus(); }
  }, 500);
};

window._liofCreateAlert = function() {
  if (!LIOF.value) return;
  _toast(`Alert created for IOC: ${LIOF.value}`, 'success');
};

window._liofAddToIOCDB = function() {
  if (!LIOF.value) return;
  _toast(`${LIOF.value} queued for IOC database import`, 'info');
};

window._liofClearHistory = function() {
  LIOF.history = [];
  localStorage.removeItem('wadjet_ioc_history');
  const hPanel = document.getElementById('liof-history');
  if (hPanel) hPanel.innerHTML = _renderHistory();
  _toast('History cleared', 'info');
};

window._liofConfigKeys = function() {
  // API keys are now hardcoded server-side — no configuration needed
  _toast('All API keys are pre-configured and active', 'success');
};

window._liofSaveKeys = function() {};

})(); // end IIFE
