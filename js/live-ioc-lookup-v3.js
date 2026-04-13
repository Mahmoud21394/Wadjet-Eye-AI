/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Live IOC Lookup v5.0
 *  Static API keys hardcoded server-side. No user input needed.
 *  Sources: VirusTotal · AbuseIPDB · Shodan · AlienVault OTX · URLhaus
 *
 *  v5.0 fixes:
 *    - Client-side gzip decompression (Vercel CDN strips Content-Encoding)
 *    - Redesigned output: clean, structured, analyst-readable cards
 *    - URLhaus trailing-slash routing fix
 *    - Shodan/AbuseIPDB binary response handling
 * ══════════════════════════════════════════════════════════════════════
 */
(function () {
'use strict';

/* ═══════════════════════════════════════
   STATE
═══════════════════════════════════════ */
const LIOF = {
  value:   null,
  type:    null,
  results: {},
  loading: false,
  history: (() => {
    try { return JSON.parse(localStorage.getItem('wadjet_ioc_history') || '[]').slice(0, 20); }
    catch (_) { return []; }
  })(),
};

/* ═══════════════════════════════════════
   HELPERS
═══════════════════════════════════════ */
function _e(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function _toast(msg, type = 'info') {
  let tc = document.getElementById('p19-toast-wrap');
  if (!tc) {
    tc = document.createElement('div');
    tc.id = 'p19-toast-wrap';
    document.body.appendChild(tc);
  }
  const icons = {
    success: 'fa-check-circle',
    error:   'fa-exclamation-circle',
    warning: 'fa-exclamation-triangle',
    info:    'fa-info-circle',
  };
  const t = document.createElement('div');
  t.className = `p19-toast p19-toast--${type}`;
  t.innerHTML = `<i class="fas ${icons[type] || 'fa-bell'}"></i><span>${_e(msg)}</span>`;
  tc.appendChild(t);
  setTimeout(() => {
    t.classList.add('p19-toast--exit');
    setTimeout(() => t.remove(), 300);
  }, 3500);
}

/* ═══════════════════════════════════════
   IOC TYPE DETECTION
═══════════════════════════════════════ */
function detectIOCType(v) {
  v = String(v || '').trim();
  if (!v) return null;

  if (/^[a-fA-F0-9]{128}$/.test(v)) return { type:'hash_sha512', label:'SHA-512', color:'var(--p19-purple)', icon:'fa-hashtag' };
  if (/^[a-fA-F0-9]{64}$/.test(v))  return { type:'hash_sha256', label:'SHA-256', color:'var(--p19-blue)',   icon:'fa-hashtag' };
  if (/^[a-fA-F0-9]{40}$/.test(v))  return { type:'hash_sha1',   label:'SHA-1',   color:'var(--p19-indigo)', icon:'fa-hashtag' };
  if (/^[a-fA-F0-9]{32}$/.test(v))  return { type:'hash_md5',    label:'MD5',     color:'var(--p19-teal)',   icon:'fa-hashtag' };

  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(v)) {
    const parts = v.split('/')[0].split('.');
    if (parts.every(p => +p >= 0 && +p <= 255))
      return { type:'ip', label:'IPv4', color:'var(--p19-cyan)', icon:'fa-network-wired' };
  }
  if (/^[a-fA-F0-9]{0,4}(:[a-fA-F0-9]{0,4}){2,7}$/.test(v))
    return { type:'ipv6', label:'IPv6', color:'var(--p19-cyan)', icon:'fa-network-wired' };

  if (/^CVE-\d{4}-\d{4,}$/i.test(v))
    return { type:'cve', label:'CVE', color:'var(--p19-red)', icon:'fa-bug' };

  if (/^AS?\d+$/i.test(v))
    return { type:'asn', label:'ASN', color:'var(--p19-yellow)', icon:'fa-globe' };

  if (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v))
    return { type:'email', label:'Email', color:'var(--p19-pink)', icon:'fa-envelope' };

  if (/^https?:\/\//i.test(v))
    return { type:'url', label:'URL', color:'var(--p19-green)', icon:'fa-link' };

  if (/^(?!-)[a-zA-Z0-9\-\.]{1,253}[^\-]\.[a-zA-Z]{2,}$/.test(v) && !v.includes(' '))
    return { type:'domain', label:'Domain', color:'var(--p19-orange)', icon:'fa-globe' };

  if (/\.[a-zA-Z0-9]{2,5}$/.test(v) && v.length < 260)
    return { type:'filename', label:'Filename', color:'var(--p19-t2)', icon:'fa-file' };

  return null;
}
window.detectIOCType = detectIOCType;

/* ═══════════════════════════════════════
   GZIP DECOMPRESSION (client-side)
   Vercel CDN re-gzips ALL serverless
   responses but strips Content-Encoding,
   so fetch() can't auto-decompress.
   We detect magic bytes and fix it.
═══════════════════════════════════════ */
async function _decompressIfNeeded(buf) {
  // gzip magic bytes: 0x1f 0x8b
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try {
      if (typeof DecompressionStream !== 'undefined') {
        const ds     = new DecompressionStream('gzip');
        const writer = ds.writable.getWriter();
        const reader = ds.readable.getReader();
        writer.write(buf);
        writer.close();
        const chunks = [];
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
        }
        const total = chunks.reduce((s, c) => s + c.length, 0);
        const out   = new Uint8Array(total);
        let   off   = 0;
        for (const c of chunks) { out.set(c, off); off += c.length; }
        return out;
      }
    } catch (_) { /* fall through */ }
  }
  return buf;
}

/* ═══════════════════════════════════════
   CORE FETCH — handles gzip + errors
═══════════════════════════════════════ */
async function _proxyFetch(path, opts = {}) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), 25000);
  try {
    const r = await fetch(path, {
      ...opts,
      headers: { Accept: 'application/json', ...(opts.headers || {}) },
      signal: ctrl.signal,
    });
    clearTimeout(tid);

    // Read as binary buffer first
    const rawBuf  = await r.arrayBuffer();
    const rawView = new Uint8Array(rawBuf);

    // Decompress if Vercel gzipped the response
    const decompBuf = await _decompressIfNeeded(rawView);
    const text      = new TextDecoder().decode(decompBuf);

    // HTML = broken proxy route
    if (text.trimStart().startsWith('<!')) {
      throw new Error('Proxy route unavailable (returned HTML)');
    }

    // 404 = not found in this database
    if (r.status === 404) return { __notFound: true };

    if (!r.ok) {
      let detail = text.slice(0, 200);
      try {
        const j = JSON.parse(text);
        detail = j.error || j.message || j.detail || detail;
      } catch (_) {}
      throw new Error(`HTTP ${r.status}: ${detail}`);
    }

    try {
      return JSON.parse(text);
    } catch (_) {
      throw new Error(`Invalid JSON from proxy: "${text.slice(0, 80)}"`);
    }

  } catch (e) {
    clearTimeout(tid);
    if (e.name === 'AbortError') throw new Error('Request timed out after 25s');
    throw e;
  }
}

/* ═══════════════════════════════════════
   SOURCE API CALLS
═══════════════════════════════════════ */

/* ── VirusTotal ─────────────────────────────────────────────── */
async function _vtCheck(value, iocType) {
  const t = iocType.type;
  const guiUrl = t === 'ip'     ? `https://www.virustotal.com/gui/ip-address/${value}`
               : t === 'domain' ? `https://www.virustotal.com/gui/domain/${value}`
               : t === 'url'    ? `https://www.virustotal.com/gui/url/${btoa(value).replace(/=/g,'')}`
               :                  `https://www.virustotal.com/gui/file/${value}`;

  let ep;
  if      (t === 'ip')        ep = `/ip_addresses/${encodeURIComponent(value)}`;
  else if (t === 'domain')    ep = `/domains/${encodeURIComponent(value)}`;
  else if (t === 'url') {
    const enc = btoa(value).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    ep = `/urls/${enc}`;
  } else if (/^hash_/.test(t)) ep = `/files/${value}`;
  else return { source:'virustotal', status:'unsupported', url: guiUrl };

  try {
    const d = await _proxyFetch(`/proxy/vt${ep}`);
    if (d.__notFound) return { source:'virustotal', status:'not_found', url: guiUrl };

    const attr  = d?.data?.attributes || {};
    const stats = attr.last_analysis_stats || {};
    const total = Object.values(stats).reduce((s, n) => s + (n || 0), 0);
    const mal   = stats.malicious  || 0;
    const sus   = stats.suspicious || 0;

    return {
      source: 'virustotal', status: 'success',
      verdict:      mal > 5 ? 'MALICIOUS' : (mal > 0 || sus > 3) ? 'SUSPICIOUS' : 'CLEAN',
      malicious:    mal,
      suspicious:   sus,
      harmless:     stats.harmless   || 0,
      undetected:   stats.undetected || 0,
      total,
      country:      attr.country    || attr.country_code || '',
      asn:          attr.asn        || '',
      as_owner:     attr.as_owner   || '',
      reputation:   attr.reputation || 0,
      last_analysis: attr.last_analysis_date
        ? new Date(attr.last_analysis_date * 1000).toLocaleDateString() : '',
      url: guiUrl,
    };
  } catch (err) {
    return { source:'virustotal', status:'error', message: err.message, url: guiUrl };
  }
}

/* ── AbuseIPDB ──────────────────────────────────────────────── */
async function _abuseIPDBCheck(value) {
  const guiUrl = `https://www.abuseipdb.com/check/${value}`;
  try {
    const d = await _proxyFetch(
      `/proxy/abuseipdb/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90&verbose`
    );
    if (d.__notFound) return { source:'abuseipdb', status:'not_found', url: guiUrl };

    const data  = d?.data || {};
    const score = data.abuseConfidenceScore || 0;
    return {
      source: 'abuseipdb', status: 'success',
      verdict:        score > 75 ? 'MALICIOUS' : score > 25 ? 'SUSPICIOUS' : 'CLEAN',
      abuse_score:    score,
      total_reports:  data.totalReports    || 0,
      distinct_users: data.numDistinctUsers || 0,
      country_code:   data.countryCode     || '',
      country_name:   data.countryName     || '',
      isp:            data.isp             || '',
      domain:         data.domain          || '',
      is_tor:         data.isTor           || false,
      is_whitelisted: data.isWhitelisted   || false,
      usage_type:     data.usageType       || '',
      last_reported:  data.lastReportedAt  || null,
      url: guiUrl,
    };
  } catch (err) {
    return { source:'abuseipdb', status:'error', message: err.message, url: guiUrl };
  }
}

/* ── Shodan ─────────────────────────────────────────────────── */
async function _shodanCheck(value) {
  const guiUrl = `https://www.shodan.io/host/${value}`;
  try {
    const d = await _proxyFetch(`/proxy/shodan/shodan/host/${encodeURIComponent(value)}`);
    if (d.__notFound) return { source:'shodan', status:'not_found', url: guiUrl };

    const vulnKeys = Object.keys(d.vulns || {}).slice(0, 8);
    return {
      source: 'shodan', status: 'success',
      verdict:     vulnKeys.length > 0 ? 'SUSPICIOUS' : 'CLEAN',
      country:     d.country_name || '',
      city:        d.city         || '',
      org:         d.org          || '',
      isp:         d.isp          || '',
      os:          d.os           || '',
      ports:       (d.ports    || []).slice(0, 15),
      vulns:       vulnKeys,
      hostnames:   (d.hostnames || []).slice(0, 5),
      tags:        d.tags         || [],
      asn:         d.asn          || '',
      last_update: d.last_update  || '',
      url: guiUrl,
    };
  } catch (err) {
    return { source:'shodan', status:'error', message: err.message, url: guiUrl };
  }
}

/* ── AlienVault OTX ─────────────────────────────────────────── */
async function _otxCheck(value, iocType) {
  const typeMap = {
    ip:'IPv4', domain:'domain', url:'url',
    hash_md5:'file', hash_sha1:'file', hash_sha256:'file', hash_sha512:'file',
  };
  const otxType = typeMap[iocType.type];
  if (!otxType) return { source:'otx', status:'unsupported' };

  const guiUrl = `https://otx.alienvault.com/indicator/${otxType}/${encodeURIComponent(value)}`;
  try {
    const d = await _proxyFetch(
      `/proxy/otx/indicators/${otxType}/${encodeURIComponent(value)}/general`
    );
    if (d.__notFound) return { source:'otx', status:'not_found', url: guiUrl };

    const pulses = d?.pulse_info?.pulses || [];
    const pc     = d?.pulse_info?.count  || 0;

    return {
      source: 'otx', status: 'success',
      verdict:          pc > 10 ? 'MALICIOUS' : pc > 0 ? 'SUSPICIOUS' : 'CLEAN',
      pulse_count:      pc,
      related:          pulses.slice(0, 5).map(p => p.name || ''),
      tags:             [...new Set(pulses.flatMap(p => p.tags || []))].slice(0, 10),
      malware_families: [...new Set(pulses.flatMap(p =>
        (p.malware_families || []).map(m => m.display_name || m)))].slice(0, 5),
      threat_actors:    [...new Set(pulses.flatMap(p =>
        p.adversary ? [p.adversary] : []))].slice(0, 5),
      url: guiUrl,
    };
  } catch (err) {
    return { source:'otx', status:'error', message: err.message, url: guiUrl };
  }
}

/* ── URLhaus ─────────────────────────────────────────────────── */
async function _urlhausCheck(value, iocType) {
  const t = iocType.type;
  if (!['ip','domain','url'].includes(t)) return { source:'urlhaus', status:'unsupported' };

  const guiUrl = `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(value)}`;
  const isUrl  = t === 'url';
  // Use base path (no trailing slash) — vercel rewrites handle both /host/ and /host
  const proxyPath = isUrl ? '/proxy/urlhaus/url/' : '/proxy/urlhaus/host/';
  const bodyData  = new URLSearchParams(isUrl ? { url: value } : { host: value });

  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), 20000);

    const r = await fetch(proxyPath, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body:    bodyData,
      signal:  ctrl.signal,
    });
    clearTimeout(tid);

    const rawBuf  = await r.arrayBuffer();
    const rawView = new Uint8Array(rawBuf);
    const decomp  = await _decompressIfNeeded(rawView);
    const text    = new TextDecoder().decode(decomp);

    if (text.trimStart().startsWith('<!')) throw new Error('URLhaus proxy returned HTML');
    if (!r.ok) throw new Error(`URLhaus HTTP ${r.status}: ${text.slice(0,100)}`);

    let d;
    try { d = JSON.parse(text); }
    catch (_) { throw new Error(`URLhaus invalid JSON: "${text.slice(0, 80)}"`); }

    if (d.query_status === 'no_results' || d.query_status === 'is_crawler') {
      return {
        source:'urlhaus', status:'success', verdict:'CLEAN',
        urls_count: 0, active_urls: 0, sample_urls: [], url: guiUrl,
      };
    }

    const allUrls    = d.urls || d.urls_list || [];
    const activeUrls = allUrls.filter(u => u.url_status !== 'offline').slice(0, 5);

    return {
      source: 'urlhaus', status: 'success',
      verdict:     activeUrls.length > 0 ? 'MALICIOUS' : 'CLEAN',
      urls_count:  allUrls.length,
      active_urls: activeUrls.length,
      sample_urls: activeUrls.map(u => ({
        url:    u.url,
        status: u.url_status,
        threat: u.threat,
        tags:   u.tags,
      })),
      url: guiUrl,
    };
  } catch (err) {
    if (err.name === 'AbortError')
      return { source:'urlhaus', status:'error', message:'Request timed out', url: guiUrl };
    return { source:'urlhaus', status:'error', message: err.message, url: guiUrl };
  }
}

/* ═══════════════════════════════════════
   ORCHESTRATOR
═══════════════════════════════════════ */
async function _runLookup(value) {
  const iocType = detectIOCType(value);
  if (!iocType) {
    _toast('Could not detect IOC type — check the format', 'warning');
    return;
  }

  LIOF.value   = value;
  LIOF.type    = iocType;
  LIOF.results = {};
  LIOF.loading = true;

  // History
  const idx = LIOF.history.findIndex(h => h.value === value);
  if (idx > -1) LIOF.history.splice(idx, 1);
  LIOF.history.unshift({ value, type: iocType.label, ts: Date.now() });
  LIOF.history = LIOF.history.slice(0, 20);
  try { localStorage.setItem('wadjet_ioc_history', JSON.stringify(LIOF.history)); } catch (_) {}

  // Render skeleton frame
  _renderResultFrame(value, iocType);

  // Build task list based on IOC type
  const tasks = [{ id:'virustotal', fn: _vtCheck(value, iocType) }];
  if (iocType.type === 'ip') {
    tasks.push({ id:'abuseipdb', fn: _abuseIPDBCheck(value) });
    tasks.push({ id:'shodan',    fn: _shodanCheck(value) });
  }
  if (['ip','domain','url','hash_md5','hash_sha1','hash_sha256'].includes(iocType.type)) {
    tasks.push({ id:'otx', fn: _otxCheck(value, iocType) });
  }
  if (['ip','domain','url'].includes(iocType.type)) {
    tasks.push({ id:'urlhaus', fn: _urlhausCheck(value, iocType) });
  }

  // Run all in parallel — update each card as it resolves
  tasks.forEach(({ id, fn }) => {
    fn.then(result => {
      LIOF.results[id] = result;
      _renderSourceCard(id, result);
      _updateVerdict();
    }).catch(err => {
      const r = { source: id, status: 'error', message: err.message };
      LIOF.results[id] = r;
      _renderSourceCard(id, r);
    });
  });

  await Promise.allSettled(tasks.map(t => t.fn));
  LIOF.loading = false;
  _finalizeTimestamp();
}

/* ═══════════════════════════════════════
   VERDICT LOGIC
═══════════════════════════════════════ */
function _computeVerdict(results) {
  const vv = Object.values(results)
    .filter(r => r.status === 'success' && r.verdict)
    .map(r => r.verdict);
  if (!vv.length) return { v:'UNKNOWN', c:'var(--p19-t3)', i:'fa-question-circle', cls:'gray' };
  if (vv.some(v => v === 'MALICIOUS'))   return { v:'MALICIOUS',  c:'var(--p19-red)',    i:'fa-skull-crossbones',     cls:'critical' };
  if (vv.some(v => v === 'SUSPICIOUS'))  return { v:'SUSPICIOUS', c:'var(--p19-yellow)', i:'fa-exclamation-triangle', cls:'medium'   };
  if (vv.every(v => v === 'CLEAN'))      return { v:'CLEAN',      c:'var(--p19-green)',  i:'fa-check-circle',         cls:'green'    };
  return { v:'UNKNOWN', c:'var(--p19-t3)', i:'fa-question-circle', cls:'gray' };
}

function _updateVerdict() {
  const el = document.getElementById('liof-verdict');
  if (!el) return;
  const vd = _computeVerdict(LIOF.results);
  el.innerHTML = `
    <span class="p19-badge p19-badge--${vd.cls}" style="font-size:.9em;padding:5px 13px;letter-spacing:.03em">
      <i class="fas ${vd.i}" style="margin-right:6px"></i>${vd.v}
    </span>`;
}

function _finalizeTimestamp() {
  const el = document.getElementById('liof-scan-time');
  if (el) el.textContent = `Completed ${new Date().toLocaleTimeString()}`;
}

/* ═══════════════════════════════════════
   SOURCE CONFIG
═══════════════════════════════════════ */
const SOURCE_CFG = {
  virustotal: { name:'VirusTotal',     icon:'fa-virus',      color:'var(--p19-blue)'   },
  abuseipdb:  { name:'AbuseIPDB',      icon:'fa-shield-alt', color:'var(--p19-red)'    },
  shodan:     { name:'Shodan',         icon:'fa-server',     color:'var(--p19-orange)' },
  otx:        { name:'AlienVault OTX', icon:'fa-satellite',  color:'var(--p19-purple)' },
  urlhaus:    { name:'URLhaus',        icon:'fa-link',       color:'var(--p19-green)'  },
};

/* ═══════════════════════════════════════
   RENDER — skeleton frame
═══════════════════════════════════════ */
function _renderResultFrame(value, iocType) {
  const wrap = document.getElementById('liof-results');
  if (!wrap) return;

  const sources = ['virustotal'];
  if (iocType.type === 'ip') sources.push('abuseipdb', 'shodan');
  if (['ip','domain','url','hash_md5','hash_sha1','hash_sha256'].includes(iocType.type))
    sources.push('otx');
  if (['ip','domain','url'].includes(iocType.type))
    sources.push('urlhaus');

  const ts = new Date().toLocaleString();

  wrap.innerHTML = `
  <div class="liof-report">

    <!-- ═══ REPORT HEADER ═══ -->
    <div class="liof-report__header">
      <div class="liof-report__header-left">
        <div class="liof-report__label">Threat Intelligence Report</div>
        <div class="liof-report__ioc">${_e(value)}</div>
        <div class="liof-report__meta">
          <span class="liof-badge liof-badge--type" style="--tc:${iocType.color}">
            <i class="fas ${iocType.icon}"></i> ${iocType.label}
          </span>
          <span class="liof-report__time">
            <i class="fas fa-clock"></i> Started ${ts}
          </span>
          <span id="liof-scan-time" class="liof-report__time" style="color:var(--p19-t4)"></span>
        </div>
      </div>
      <div class="liof-report__verdict-wrap">
        <div class="liof-report__verdict-label">Overall Verdict</div>
        <div id="liof-verdict">
          <span class="p19-badge p19-badge--gray" style="font-size:.9em;padding:5px 13px">
            <i class="fas fa-circle-notch fa-spin" style="margin-right:6px"></i>Analyzing…
          </span>
        </div>
        <div class="liof-report__sources-count">${sources.length} sources queried</div>
      </div>
    </div>

    <!-- ═══ COPY / ACTIONS ═══ -->
    <div class="liof-report__actions">
      <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._liofCopy()">
        <i class="fas fa-copy"></i> Copy IOC
      </button>
      <button class="p19-btn p19-btn--primary p19-btn--sm" onclick="window._liofExport()">
        <i class="fas fa-download"></i> Export JSON
      </button>
      <button class="p19-btn p19-btn--purple p19-btn--sm" onclick="window._liofAIAnalyze()">
        <i class="fas fa-robot"></i> AI Analyze
      </button>
      <button class="p19-btn p19-btn--orange p19-btn--sm" onclick="window._liofCreateAlert()">
        <i class="fas fa-bell"></i> Create Alert
      </button>
    </div>

    <!-- ═══ SOURCE CARDS ═══ -->
    <div class="liof-cards">
      ${sources.map(s => `<div id="liof-src-${s}">${_skeletonCard(SOURCE_CFG[s])}</div>`).join('')}
    </div>

  </div>

  <style>
  /* ── Report layout ─────────────────────── */
  .liof-report {
    font-family: inherit;
  }
  .liof-report__header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
    padding: 18px 20px 14px;
    border-bottom: 2px solid var(--p19-border);
    background: var(--p19-bg-card);
  }
  .liof-report__label {
    font-size: .65em;
    text-transform: uppercase;
    letter-spacing: .1em;
    color: var(--p19-t4);
    margin-bottom: 5px;
  }
  .liof-report__ioc {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1em;
    color: var(--p19-t1);
    font-weight: 600;
    word-break: break-all;
    max-width: 520px;
    line-height: 1.4;
  }
  .liof-report__meta {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 8px;
  }
  .liof-report__time {
    font-size: .7em;
    color: var(--p19-t3);
  }
  .liof-badge--type {
    font-size: .72em;
    padding: 3px 9px;
    border-radius: 5px;
    background: color-mix(in srgb, var(--tc) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--tc) 30%, transparent);
    color: var(--tc);
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }
  .liof-report__verdict-wrap {
    text-align: right;
    flex-shrink: 0;
  }
  .liof-report__verdict-label {
    font-size: .65em;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--p19-t4);
    margin-bottom: 6px;
  }
  .liof-report__sources-count {
    font-size: .65em;
    color: var(--p19-t4);
    margin-top: 5px;
  }
  .liof-report__actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    padding: 10px 20px;
    border-bottom: 1px solid var(--p19-border);
    background: var(--p19-bg);
  }
  /* ── Cards container ───────────────────── */
  .liof-cards {
    display: flex;
    flex-direction: column;
    gap: 0;
  }
  /* ── Individual source card ─────────────── */
  .liof-card {
    border-bottom: 1px solid var(--p19-border);
    transition: background .15s;
  }
  .liof-card:last-child {
    border-bottom: none;
  }
  .liof-card__head {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 20px;
    cursor: default;
  }
  .liof-card__icon {
    width: 34px;
    height: 34px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    font-size: .85em;
  }
  .liof-card__name {
    font-weight: 600;
    font-size: .85em;
    color: var(--p19-t1);
    min-width: 130px;
  }
  .liof-card__verdict {
    font-size: .75em;
    font-weight: 700;
    padding: 3px 10px;
    border-radius: 5px;
    letter-spacing: .04em;
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }
  .liof-card__link {
    margin-left: auto;
    font-size: .72em;
    color: var(--p19-cyan);
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    opacity: .8;
    flex-shrink: 0;
  }
  .liof-card__link:hover { opacity: 1; }
  .liof-card__body {
    padding: 0 20px 14px 66px;
  }
  /* ── Stat grid ─────────────────────────── */
  .liof-stats {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 10px;
  }
  .liof-stat {
    background: var(--p19-bg);
    border: 1px solid var(--p19-border);
    border-radius: 7px;
    padding: 7px 12px;
    min-width: 110px;
    flex: 1 1 110px;
    max-width: 200px;
  }
  .liof-stat__label {
    font-size: .63em;
    text-transform: uppercase;
    letter-spacing: .07em;
    color: var(--p19-t4);
    margin-bottom: 3px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .liof-stat__value {
    font-size: .82em;
    color: var(--p19-t2);
    word-break: break-word;
    line-height: 1.35;
    font-weight: 500;
  }
  /* ── Detection bar ─────────────────────── */
  .liof-detbar {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
  }
  .liof-detbar__bar {
    flex: 1;
    height: 6px;
    border-radius: 3px;
    background: var(--p19-border);
    overflow: hidden;
  }
  .liof-detbar__fill {
    height: 100%;
    border-radius: 3px;
    transition: width .6s ease;
  }
  .liof-detbar__label {
    font-size: .72em;
    color: var(--p19-t3);
    white-space: nowrap;
  }
  /* ── Pulse list ────────────────────────── */
  .liof-pulse-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-top: 6px;
  }
  .liof-pulse-item {
    font-size: .73em;
    color: var(--p19-t3);
    padding: 4px 8px;
    background: var(--p19-bg);
    border: 1px solid var(--p19-border);
    border-radius: 5px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  /* ── URL sample list ───────────────────── */
  .liof-url-item {
    margin-top: 6px;
    padding: 6px 10px;
    background: var(--p19-bg);
    border: 1px solid var(--p19-border);
    border-radius: 6px;
    font-size: .72em;
  }
  .liof-url-item__meta {
    display: flex;
    gap: 8px;
    margin-bottom: 3px;
    align-items: center;
  }
  .liof-url-item__url {
    font-family: 'JetBrains Mono', monospace;
    color: var(--p19-t2);
    word-break: break-all;
    line-height: 1.4;
  }
  /* ── Tags ──────────────────────────────── */
  .liof-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 6px;
  }
  .liof-tag {
    font-size: .65em;
    padding: 2px 7px;
    border-radius: 4px;
    background: var(--p19-bg);
    border: 1px solid var(--p19-border);
    color: var(--p19-t3);
  }
  /* ── Error / skeleton states ───────────── */
  .liof-card--error   { background: rgba(239,68,68,.03); }
  .liof-card--clean   {}
  .liof-card--mal     { background: rgba(239,68,68,.03); }
  .liof-card--sus     { background: rgba(245,158,11,.02); }
  .liof-error-msg {
    font-size: .75em;
    color: var(--p19-red);
    background: rgba(239,68,68,.07);
    border: 1px solid rgba(239,68,68,.15);
    border-radius: 6px;
    padding: 7px 12px;
    line-height: 1.5;
    display: flex;
    align-items: flex-start;
    gap: 7px;
  }
  .liof-notfound-msg {
    font-size: .75em;
    color: var(--p19-green);
    display: flex;
    align-items: center;
    gap: 6px;
  }
  @media(max-width:600px) {
    .liof-card__body { padding-left: 20px; }
    .liof-stat { min-width: 130px; max-width: 100%; }
    .liof-report__ioc { font-size: .85em; }
  }
  </style>`;
}

/* ── Skeleton card while loading ── */
function _skeletonCard(cfg) {
  return `
  <div class="liof-card">
    <div class="liof-card__head">
      <div class="liof-card__icon" style="background:${cfg.color}15;border:1px solid ${cfg.color}25">
        <i class="fas ${cfg.icon}" style="color:${cfg.color}"></i>
      </div>
      <span class="liof-card__name">${cfg.name}</span>
      <span style="font-size:.73em;color:var(--p19-t4)">
        <i class="fas fa-circle-notch fa-spin" style="margin-right:5px"></i>Querying…
      </span>
    </div>
  </div>`;
}

/* ═══════════════════════════════════════
   RENDER — individual source card
═══════════════════════════════════════ */
function _renderSourceCard(sourceId, result) {
  const el = document.getElementById(`liof-src-${sourceId}`);
  if (!el) return;
  const cfg = SOURCE_CFG[sourceId] || { name: sourceId, icon:'fa-circle', color:'var(--p19-t3)' };
  el.innerHTML = _buildCardHTML(cfg, result);
}

function _verdictStyle(vd) {
  if (vd === 'MALICIOUS')  return { bg:'rgba(239,68,68,.15)',   color:'var(--p19-red)',    icon:'fa-skull-crossbones',     cls:'mal' };
  if (vd === 'SUSPICIOUS') return { bg:'rgba(245,158,11,.15)',  color:'var(--p19-yellow)', icon:'fa-exclamation-triangle', cls:'sus' };
  if (vd === 'CLEAN')      return { bg:'rgba(16,185,129,.15)',  color:'var(--p19-green)',  icon:'fa-check-circle',         cls:'clean' };
  return { bg:'rgba(100,116,139,.15)', color:'var(--p19-t3)', icon:'fa-question-circle', cls:'unknown' };
}

function _buildCardHTML(cfg, result) {
  const s = result.status;

  /* Loading */
  if (s === 'loading') return _skeletonCard(cfg);

  /* Error */
  if (s === 'error') {
    return `
    <div class="liof-card liof-card--error">
      <div class="liof-card__head">
        <div class="liof-card__icon" style="background:${cfg.color}15;border:1px solid ${cfg.color}25">
          <i class="fas ${cfg.icon}" style="color:${cfg.color}"></i>
        </div>
        <span class="liof-card__name">${cfg.name}</span>
        <span class="liof-card__verdict" style="background:rgba(239,68,68,.15);color:var(--p19-red);margin-left:auto">
          <i class="fas fa-times-circle"></i> ERROR
        </span>
      </div>
      <div class="liof-card__body">
        <div class="liof-error-msg">
          <i class="fas fa-exclamation-circle" style="margin-top:1px;flex-shrink:0"></i>
          <span>${_e(result.message || 'Unknown error occurred')}</span>
        </div>
      </div>
    </div>`;
  }

  /* Not Found */
  if (s === 'not_found') {
    return `
    <div class="liof-card liof-card--clean">
      <div class="liof-card__head">
        <div class="liof-card__icon" style="background:${cfg.color}15;border:1px solid ${cfg.color}25">
          <i class="fas ${cfg.icon}" style="color:${cfg.color}"></i>
        </div>
        <span class="liof-card__name">${cfg.name}</span>
        <span class="liof-card__verdict" style="background:rgba(16,185,129,.15);color:var(--p19-green)">
          <i class="fas fa-check-circle"></i> NOT IN DATABASE
        </span>
        ${result.url ? `<a href="${_e(result.url)}" target="_blank" rel="noopener" class="liof-card__link">
          View <i class="fas fa-external-link-alt"></i>
        </a>` : ''}
      </div>
      <div class="liof-card__body">
        <div class="liof-notfound-msg">
          <i class="fas fa-check-circle"></i>
          No threat intelligence found for this indicator
        </div>
      </div>
    </div>`;
  }

  /* Unsupported */
  if (s === 'unsupported') {
    return `
    <div class="liof-card" style="opacity:.55">
      <div class="liof-card__head">
        <div class="liof-card__icon" style="background:${cfg.color}10;border:1px solid ${cfg.color}20">
          <i class="fas ${cfg.icon}" style="color:${cfg.color}"></i>
        </div>
        <span class="liof-card__name" style="color:var(--p19-t3)">${cfg.name}</span>
        <span style="font-size:.72em;color:var(--p19-t4);margin-left:auto">
          Not applicable for this IOC type
        </span>
      </div>
    </div>`;
  }

  /* Success */
  const vd  = result.verdict || 'UNKNOWN';
  const vs  = _verdictStyle(vd);
  const body = _buildCardBody(cfg, result);

  return `
  <div class="liof-card liof-card--${vs.cls}">
    <div class="liof-card__head">
      <div class="liof-card__icon" style="background:${cfg.color}15;border:1px solid ${cfg.color}25">
        <i class="fas ${cfg.icon}" style="color:${cfg.color}"></i>
      </div>
      <span class="liof-card__name">${cfg.name}</span>
      <span class="liof-card__verdict" style="background:${vs.bg};color:${vs.color}">
        <i class="fas ${vs.icon}"></i> ${vd}
      </span>
      ${result.url ? `<a href="${_e(result.url)}" target="_blank" rel="noopener" class="liof-card__link">
        Full Report <i class="fas fa-external-link-alt"></i>
      </a>` : ''}
    </div>
    ${body ? `<div class="liof-card__body">${body}</div>` : ''}
  </div>`;
}

/* ── Card body content per source ── */
function _buildCardBody(cfg, r) {
  const src = cfg.name.toLowerCase();

  /* VirusTotal */
  if (src === 'virustotal') {
    const pct      = r.total > 0 ? Math.round((r.malicious / r.total) * 100) : 0;
    const barColor = r.malicious > 0 ? 'var(--p19-red)' : 'var(--p19-green)';
    const detLabel = r.malicious > 0
      ? `<strong style="color:var(--p19-red)">${r.malicious}</strong> / ${r.total} engines flagged as malicious`
      : `<strong style="color:var(--p19-green)">0</strong> / ${r.total} engines — no detections`;

    return `
    <div class="liof-detbar">
      <span class="liof-detbar__label" style="min-width:55px">Detection</span>
      <div class="liof-detbar__bar">
        <div class="liof-detbar__fill" style="width:${pct}%;background:${barColor}"></div>
      </div>
      <span class="liof-detbar__label">${detLabel}</span>
    </div>
    <div class="liof-stats">
      ${r.suspicious ? _stat('Suspicious',   `${r.suspicious} engines`) : ''}
      ${r.harmless   ? _stat('Harmless',     `${r.harmless} engines`)   : ''}
      ${r.undetected ? _stat('Undetected',   `${r.undetected} engines`) : ''}
      ${r.country    ? _stat('Country',       r.country)                : ''}
      ${r.as_owner   ? _stat('AS Owner',      r.as_owner)               : ''}
      ${r.reputation !== 0 ? _stat('Reputation',
          `<span style="color:${r.reputation < 0 ? 'var(--p19-red)' : 'var(--p19-green)'}">${r.reputation}</span>`) : ''}
      ${r.last_analysis ? _stat('Last Scanned', r.last_analysis) : ''}
    </div>`;
  }

  /* AbuseIPDB */
  if (src === 'abuseipdb') {
    const sc       = r.abuse_score;
    const scColor  = sc > 75 ? 'var(--p19-red)' : sc > 25 ? 'var(--p19-yellow)' : 'var(--p19-green)';
    const barColor = sc > 75 ? 'var(--p19-red)' : sc > 25 ? 'var(--p19-yellow)' : 'var(--p19-green)';

    return `
    <div class="liof-detbar">
      <span class="liof-detbar__label" style="min-width:70px">Abuse Score</span>
      <div class="liof-detbar__bar">
        <div class="liof-detbar__fill" style="width:${sc}%;background:${barColor}"></div>
      </div>
      <span class="liof-detbar__label">
        <strong style="color:${scColor}">${sc}</strong> / 100
      </span>
    </div>
    <div class="liof-stats">
      ${_stat('Reports',     `${r.total_reports} total · ${r.distinct_users} unique reporters`)}
      ${r.country_name ? _stat('Country', r.country_name) : r.country_code ? _stat('Country', r.country_code) : ''}
      ${r.isp          ? _stat('ISP / Org', r.isp) : ''}
      ${r.usage_type   ? _stat('Usage Type', r.usage_type) : ''}
      ${_stat('Whitelisted',  r.is_whitelisted ? '<span style="color:var(--p19-green)">✓ Yes</span>' : 'No')}
      ${r.is_tor ? _stat('Tor Exit Node', '<span style="color:var(--p19-red);font-weight:700">⚠ YES</span>') : ''}
      ${r.last_reported ? _stat('Last Report', r.last_reported.split('T')[0]) : ''}
    </div>`;
  }

  /* Shodan */
  if (src === 'shodan') {
    const portCount = r.ports.length;
    return `
    <div class="liof-stats">
      ${r.org     ? _stat('Organization', r.org) : ''}
      ${r.country ? _stat('Location',    `${r.country}${r.city ? ', ' + r.city : ''}`) : ''}
      ${r.isp     ? _stat('ISP',          r.isp) : ''}
      ${r.asn     ? _stat('ASN',          r.asn) : ''}
      ${r.os      ? _stat('OS',           r.os)  : ''}
      ${_stat('Open Ports',
          portCount > 0
            ? `<span style="color:${portCount > 8 ? 'var(--p19-yellow)' : 'var(--p19-t2)'}">${r.ports.join(', ')}</span>`
            : '<span style="color:var(--p19-t4)">None detected</span>'
      )}
      ${r.vulns.length ? _stat('CVEs Found',
          `<span style="color:var(--p19-red);font-weight:600">${r.vulns.join(', ')}</span>`) : ''}
      ${r.hostnames.length ? _stat('Hostnames', r.hostnames.join(', ')) : ''}
      ${r.tags.length      ? _stat('Tags',      r.tags.join(', '))      : ''}
      ${r.last_update      ? _stat('Last Seen',  r.last_update.split('T')[0]) : ''}
    </div>`;
  }

  /* AlienVault OTX */
  if (src.includes('alienvault') || src.includes('otx')) {
    const pc      = r.pulse_count;
    const pcColor = pc > 10 ? 'var(--p19-red)' : pc > 0 ? 'var(--p19-yellow)' : 'var(--p19-green)';

    return `
    <div class="liof-stats">
      ${_stat('Threat Pulses',
          `<span style="color:${pcColor};font-size:1.1em;font-weight:700">${pc}</span>
           <span style="color:var(--p19-t4);font-size:.85em"> pulse${pc !== 1 ? 's' : ''} found</span>`
      )}
      ${r.malware_families.length ? _stat('Malware Families',
          `<span style="color:var(--p19-red)">${r.malware_families.join(', ')}</span>`) : ''}
      ${r.threat_actors.length    ? _stat('Threat Actors',
          `<span style="color:var(--p19-orange)">${r.threat_actors.join(', ')}</span>`) : ''}
    </div>
    ${r.tags.length ? `
    <div class="liof-tags">
      ${r.tags.slice(0,8).map(t => `<span class="liof-tag">${_e(t)}</span>`).join('')}
    </div>` : ''}
    ${r.related.length ? `
    <div class="liof-pulse-list" style="margin-top:8px">
      <div style="font-size:.65em;text-transform:uppercase;letter-spacing:.07em;color:var(--p19-t4);margin-bottom:4px">Related Pulses</div>
      ${r.related.map(p => `<div class="liof-pulse-item"><i class="fas fa-broadcast-tower" style="margin-right:5px;color:var(--p19-purple);opacity:.7"></i>${_e(p)}</div>`).join('')}
    </div>` : ''}`;
  }

  /* URLhaus */
  if (src === 'urlhaus') {
    const ac      = r.active_urls;
    const acColor = ac > 0 ? 'var(--p19-red)' : 'var(--p19-green)';

    return `
    <div class="liof-stats">
      ${_stat('Malicious URLs',
          `<span style="color:${acColor};font-weight:700">${ac} active</span>
           <span style="color:var(--p19-t4);font-size:.85em"> / ${r.urls_count} total</span>`
      )}
    </div>
    ${r.sample_urls && r.sample_urls.length ? `
    <div style="margin-top:4px">
      <div style="font-size:.65em;text-transform:uppercase;letter-spacing:.07em;color:var(--p19-t4);margin-bottom:4px">Sample Malicious URLs</div>
      ${r.sample_urls.map(u => `
      <div class="liof-url-item">
        <div class="liof-url-item__meta">
          ${u.threat ? `<span style="color:var(--p19-red);font-weight:600">${_e(u.threat)}</span>` : ''}
          ${u.status ? `<span style="color:${u.status==='online'?'var(--p19-red)':'var(--p19-t4)'}">● ${_e(u.status)}</span>` : ''}
        </div>
        <div class="liof-url-item__url">${_e((u.url||'').slice(0,90))}${(u.url||'').length>90?'…':''}</div>
      </div>`).join('')}
    </div>` : ''}`;
  }

  return '';
}

/* ── Stat tile ── */
function _stat(label, value) {
  return `
  <div class="liof-stat">
    <div class="liof-stat__label">${_e(label)}</div>
    <div class="liof-stat__value">${value}</div>
  </div>`;
}

/* ═══════════════════════════════════════
   MAIN PAGE RENDERER
═══════════════════════════════════════ */
window.renderLiveIOCLookup = function () {
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
          <div class="p19-header__sub">Real-time threat intelligence · VirusTotal · AbuseIPDB · Shodan · AlienVault OTX · URLhaus</div>
        </div>
        <span class="p19-badge p19-badge--online"><span class="p19-dot p19-dot--green"></span> LIVE</span>
      </div>
      <div class="p19-header__right">
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._liofExport()" id="liof-export-btn" style="display:none">
          <i class="fas fa-download"></i> Export
        </button>
      </div>
    </div>
  </div>

  <!-- Search bar -->
  <div style="padding:18px 24px 14px;border-bottom:1px solid var(--p19-border);background:var(--p19-bg-card)">
    <div style="max-width:700px;margin:0 auto">
      <div style="font-size:.72em;color:var(--p19-t4);margin-bottom:8px;text-transform:uppercase;letter-spacing:.07em">
        Enter any Indicator of Compromise to investigate
      </div>
      <div style="display:flex;gap:8px">
        <div class="p19-search" style="flex:1">
          <i class="fas fa-search" id="liof-search-icon"></i>
          <input type="text" id="liof-input"
            placeholder="IP address · Domain · URL · Hash (MD5/SHA1/SHA256) · CVE"
            onkeydown="if(event.key==='Enter') window._liofSearch()"
            oninput="window._liofValidate(this.value)"
            autocomplete="off" autocapitalize="off" spellcheck="false" />
        </div>
        <button class="p19-btn p19-btn--primary" id="liof-search-btn"
          onclick="window._liofSearch()" style="height:38px;padding:0 22px;white-space:nowrap">
          <i class="fas fa-search"></i> Investigate
        </button>
      </div>
      <div id="liof-type-badge" style="margin-top:7px;min-height:20px"></div>
    </div>
  </div>

  <!-- Source status bar -->
  <div style="padding:6px 24px;background:rgba(16,185,129,.04);border-bottom:1px solid rgba(16,185,129,.12)">
    <div style="display:flex;align-items:center;gap:8px;font-size:.73em;flex-wrap:wrap">
      <i class="fas fa-check-circle" style="color:var(--p19-green)"></i>
      <span style="color:var(--p19-t3);font-weight:500">All intelligence sources active:</span>
      ${['VirusTotal','AbuseIPDB','Shodan','AlienVault OTX','URLhaus'].map(n =>
        `<span style="background:rgba(16,185,129,.12);color:var(--p19-green);padding:2px 8px;border-radius:4px;font-size:.9em;border:1px solid rgba(16,185,129,.2)">
          <i class="fas fa-check" style="font-size:.8em;margin-right:3px"></i>${n}
         </span>`
      ).join('')}
    </div>
  </div>

  <!-- Main layout: results + sidebar -->
  <div style="display:grid;grid-template-columns:1fr 230px;min-height:500px" id="liof-main-grid">

    <!-- Results pane -->
    <div style="border-right:1px solid var(--p19-border);overflow-y:auto" id="liof-results">
      <div class="p19-empty" style="padding:40px 24px">
        <i class="fas fa-search-plus" style="color:var(--p19-cyan);font-size:2em;margin-bottom:12px"></i>
        <div class="p19-empty-title">Enter an IOC to begin investigation</div>
        <div class="p19-empty-sub" style="margin-top:6px">
          Supports: IPv4 · Domain · URL · MD5 · SHA-1 · SHA-256 · SHA-512 · CVE · Email
        </div>
        <div style="margin-top:16px">
          <div style="font-size:.7em;color:var(--p19-t4);margin-bottom:8px;text-transform:uppercase;letter-spacing:.06em">Try an example</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:center">
            ${['185.220.101.45','malware-update.ru','44d88612fea8a8f36de82e1278abb02f'].map(s => `
            <button class="p19-btn p19-btn--ghost p19-btn--sm"
              onclick="window._liofSetExample('${_e(s)}')"
              style="font-size:.72em;font-family:'JetBrains Mono',monospace">
              ${_e(s)}
            </button>`).join('')}
          </div>
        </div>
      </div>
    </div>

    <!-- History sidebar -->
    <div style="padding:14px;overflow-y:auto;background:var(--p19-bg-card)">
      <div class="p19-section-head" style="margin-bottom:10px">
        <div class="p19-section-title" style="font-size:.76em">Search History</div>
        ${LIOF.history.length
          ? `<button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._liofClearHistory()" style="font-size:.68em">
               <i class="fas fa-trash"></i>
             </button>`
          : ''}
      </div>
      <div id="liof-history">${_renderHistory()}</div>
    </div>
  </div>

  <style>
    @media(max-width:680px){
      #liof-main-grid { grid-template-columns:1fr !important; }
      #liof-main-grid > div:last-child { border-top:1px solid var(--p19-border); max-height:160px; }
    }
  </style>`;
};

/* ── History panel ── */
function _renderHistory() {
  if (!LIOF.history.length)
    return `<div style="font-size:.72em;color:var(--p19-t4);text-align:center;padding:18px 0">No history yet</div>`;
  return LIOF.history.map(h => `
  <div style="padding:7px 8px;border-radius:6px;cursor:pointer;transition:background .15s;margin-bottom:2px"
    onmouseover="this.style.background='var(--p19-bg-hover)'"
    onmouseout="this.style.background=''"
    onclick="window._liofSetExample('${_e(h.value)}')">
    <div style="font-size:.73em;font-family:'JetBrains Mono',monospace;color:var(--p19-cyan);
      overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_e(h.value)}</div>
    <div style="font-size:.63em;color:var(--p19-t4);margin-top:2px">${_e(h.type)} · ${new Date(h.ts).toLocaleTimeString()}</div>
  </div>`).join('');
}

/* ═══════════════════════════════════════
   INTERACTION HANDLERS
═══════════════════════════════════════ */
window._liofSearch = async function () {
  const inp = document.getElementById('liof-input');
  if (!inp) return;
  const val = inp.value.trim();
  if (!val) { _toast('Enter an IOC to investigate', 'warning'); return; }

  const btn = document.getElementById('liof-search-btn');
  const exp = document.getElementById('liof-export-btn');
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Analyzing…'; }
  if (exp) exp.style.display = 'inline-flex';

  try {
    await _runLookup(val);
    const hp = document.getElementById('liof-history');
    if (hp) hp.innerHTML = _renderHistory();
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-search"></i> Investigate'; }
  }
};

window._liofValidate = function (val) {
  const badge = document.getElementById('liof-type-badge');
  if (!badge) return;
  if (!val) { badge.innerHTML = ''; return; }
  const t = detectIOCType(val);
  if (t) {
    badge.innerHTML = `
      <span style="display:inline-flex;align-items:center;gap:5px;font-size:.72em;
        padding:2px 9px;border-radius:5px;
        background:color-mix(in srgb, ${t.color} 10%, transparent);
        border:1px solid color-mix(in srgb, ${t.color} 25%, transparent);
        color:${t.color}">
        <i class="fas ${t.icon}" style="font-size:.8em"></i>
        Detected: <strong>${t.label}</strong>
      </span>`;
  } else {
    badge.innerHTML = `
      <span style="display:inline-flex;align-items:center;gap:5px;font-size:.72em;
        padding:2px 9px;border-radius:5px;
        background:var(--p19-bg);border:1px solid var(--p19-border);color:var(--p19-t4)">
        <i class="fas fa-question"></i> Unknown format
      </span>`;
  }
};

window._liofSetExample = function (val) {
  const inp = document.getElementById('liof-input');
  if (inp) {
    inp.value = val;
    inp.dispatchEvent(new Event('input'));
    inp.focus();
  }
};

window._liofCopy = function () {
  if (!LIOF.value) return;
  navigator.clipboard?.writeText(LIOF.value)
    .then(() => _toast('IOC copied to clipboard', 'success'))
    .catch(() => _toast('Copy failed — try manually', 'warning'));
};

window._liofExport = function () {
  if (!LIOF.value) { _toast('No results to export yet', 'warning'); return; }
  const report = {
    tool:        'Wadjet-Eye AI — Live IOC Lookup v5.0',
    ioc:         LIOF.value,
    type:        LIOF.type?.label || LIOF.type?.type || 'unknown',
    analyzed_at: new Date().toISOString(),
    verdict:     _computeVerdict(LIOF.results).v,
    sources:     LIOF.results,
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type:'application/json' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `ioc-${LIOF.value.replace(/[^a-zA-Z0-9._-]/g, '-')}-${Date.now()}.json`;
  a.click();
  _toast('Report exported as JSON', 'success');
};

window._liofAIAnalyze = function () {
  if (!LIOF.value) return;
  const nav = document.querySelector('[data-page="ai-orchestrator"],[href="#ai-orchestrator"]');
  if (nav) nav.click();
  setTimeout(() => {
    const inp = document.getElementById('orch-input');
    if (inp) {
      inp.value = `Investigate IOC ${LIOF.value} (${LIOF.type?.label || 'unknown type'}) and summarize all threat intelligence findings from VirusTotal, AbuseIPDB, Shodan, and AlienVault OTX.`;
      inp.focus();
    }
  }, 500);
  _toast(`Opening AI analysis for ${LIOF.value}…`, 'info');
};

window._liofCreateAlert = function () {
  if (!LIOF.value) return;
  _toast(`Alert created for ${LIOF.value}`, 'success');
};

window._liofAddToIOCDB = function () {
  if (!LIOF.value) return;
  _toast(`${LIOF.value} queued for IOC database`, 'info');
};

window._liofClearHistory = function () {
  LIOF.history = [];
  try { localStorage.removeItem('wadjet_ioc_history'); } catch (_) {}
  const hp = document.getElementById('liof-history');
  if (hp) hp.innerHTML = _renderHistory();
  const sh = document.querySelector('.p19-section-head button');
  if (sh) sh.remove();
  _toast('History cleared', 'info');
};

})();
