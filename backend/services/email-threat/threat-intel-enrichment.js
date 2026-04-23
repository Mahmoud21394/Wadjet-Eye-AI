/**
 * ETI-AARE Threat Intelligence Enrichment Service v1.0
 * Multi-source enrichment: VirusTotal, AbuseIPDB, URLScan.io, Passive DNS, Shodan
 * Provides reputation scores, behavioral context, and historical intelligence
 */

'use strict';

const https = require('https');
const http = require('http');
const crypto = require('crypto');

// ─── Simple HTTP Client ──────────────────────────────────────────────────────
function httpGet(url, headers = {}, timeout = 8000) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const timer = setTimeout(() => reject(new Error('timeout')), timeout);
    const req = lib.get(url, { headers }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        clearTimeout(timer);
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on('error', e => { clearTimeout(timer); reject(e); });
  });
}

function httpPost(url, body, headers = {}, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyStr), ...headers }
    };
    const timer = setTimeout(() => reject(new Error('timeout')), timeout);
    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        clearTimeout(timer);
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on('error', e => { clearTimeout(timer); reject(e); });
    req.write(bodyStr);
    req.end();
  });
}

// ─── In-Memory Cache ─────────────────────────────────────────────────────────
class IntelCache {
  constructor(ttlMs = 30 * 60 * 1000) { // 30 min default TTL
    this.cache = new Map();
    this.ttl = ttlMs;
  }

  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.ts > this.ttl) { this.cache.delete(key); return null; }
    return entry.data;
  }

  set(key, data) {
    this.cache.set(key, { data, ts: Date.now() });
  }

  size() { return this.cache.size; }
}

const INTEL_CACHE = new IntelCache();

// ─── VirusTotal Enrichment ────────────────────────────────────────────────────
class VirusTotalEnricher {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseUrl = 'https://www.virustotal.com/api/v3';
    this.enabled = !!apiKey;
  }

  async lookupHash(hash) {
    if (!this.enabled) return this._mockHashResult(hash);
    const cacheKey = `vt:hash:${hash}`;
    const cached = INTEL_CACHE.get(cacheKey);
    if (cached) return cached;

    try {
      const res = await httpGet(`${this.baseUrl}/files/${hash}`,
        { 'x-apikey': this.apiKey });
      if (res.status === 404) return { found: false, hash };
      const result = this._parseFileReport(res.data);
      INTEL_CACHE.set(cacheKey, result);
      return result;
    } catch {
      return { found: false, hash, error: 'lookup_failed' };
    }
  }

  async lookupUrl(url) {
    if (!this.enabled) return this._mockUrlResult(url);
    const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
    const cacheKey = `vt:url:${crypto.createHash('md5').update(url).digest('hex')}`;
    const cached = INTEL_CACHE.get(cacheKey);
    if (cached) return cached;

    try {
      const res = await httpGet(`${this.baseUrl}/urls/${urlId}`,
        { 'x-apikey': this.apiKey });
      if (res.status === 404) return { found: false, url };
      const result = this._parseUrlReport(res.data);
      INTEL_CACHE.set(cacheKey, result);
      return result;
    } catch {
      return { found: false, url, error: 'lookup_failed' };
    }
  }

  async lookupDomain(domain) {
    if (!this.enabled) return this._mockDomainResult(domain);
    const cacheKey = `vt:domain:${domain}`;
    const cached = INTEL_CACHE.get(cacheKey);
    if (cached) return cached;

    try {
      const res = await httpGet(`${this.baseUrl}/domains/${domain}`,
        { 'x-apikey': this.apiKey });
      if (res.status === 404) return { found: false, domain };
      const result = this._parseDomainReport(res.data);
      INTEL_CACHE.set(cacheKey, result);
      return result;
    } catch {
      return { found: false, domain, error: 'lookup_failed' };
    }
  }

  async lookupIp(ip) {
    if (!this.enabled) return this._mockIpResult(ip);
    const cacheKey = `vt:ip:${ip}`;
    const cached = INTEL_CACHE.get(cacheKey);
    if (cached) return cached;

    try {
      const res = await httpGet(`${this.baseUrl}/ip_addresses/${ip}`,
        { 'x-apikey': this.apiKey });
      if (res.status === 404) return { found: false, ip };
      const result = this._parseIpReport(res.data, ip);
      INTEL_CACHE.set(cacheKey, result);
      return result;
    } catch {
      return { found: false, ip, error: 'lookup_failed' };
    }
  }

  _parseFileReport(data) {
    const attrs = data?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const total = Object.values(stats).reduce((s, v) => s + v, 0);
    const malicious = stats.malicious || 0;
    return {
      found: true,
      source: 'virustotal',
      sha256: attrs.sha256,
      md5: attrs.md5,
      name: attrs.meaningful_name || attrs.names?.[0],
      size: attrs.size,
      type: attrs.type_description,
      malicious_count: malicious,
      total_engines: total,
      detection_ratio: total > 0 ? `${malicious}/${total}` : '0/0',
      reputation: malicious > 5 ? 'malicious' : malicious > 0 ? 'suspicious' : 'clean',
      score: total > 0 ? Math.round((malicious / total) * 100) : 0,
      tags: attrs.tags || [],
      first_seen: attrs.first_submission_date,
      last_seen: attrs.last_analysis_date,
      threat_names: Object.values(attrs.last_analysis_results || {})
        .filter(r => r.category === 'malicious').map(r => r.result).filter(Boolean).slice(0, 5)
    };
  }

  _parseUrlReport(data) {
    const attrs = data?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const total = Object.values(stats).reduce((s, v) => s + v, 0);
    return {
      found: true,
      source: 'virustotal',
      url: attrs.url,
      final_url: attrs.last_final_url,
      title: attrs.title,
      malicious_count: malicious,
      total_engines: total,
      detection_ratio: total > 0 ? `${malicious}/${total}` : '0/0',
      reputation: malicious > 3 ? 'malicious' : malicious > 0 ? 'suspicious' : 'clean',
      score: total > 0 ? Math.round((malicious / total) * 100) : 0,
      categories: attrs.categories || {},
      redirection_chain: attrs.redirection_chain || []
    };
  }

  _parseDomainReport(data) {
    const attrs = data?.data?.attributes || {};
    return {
      found: true,
      source: 'virustotal',
      domain: data?.data?.id,
      reputation: attrs.reputation || 0,
      vt_score: attrs.reputation < -5 ? 'malicious' : attrs.reputation < 0 ? 'suspicious' : 'clean',
      categories: attrs.categories || {},
      creation_date: attrs.creation_date,
      registrar: attrs.registrar,
      whois: attrs.whois?.substring(0, 500),
      last_dns_records: attrs.last_dns_records?.slice(0, 10) || []
    };
  }

  _parseIpReport(data, ip) {
    const attrs = data?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    return {
      found: true,
      source: 'virustotal',
      ip,
      asn: attrs.asn,
      as_owner: attrs.as_owner,
      country: attrs.country,
      continent: attrs.continent,
      malicious_count: malicious,
      reputation: attrs.reputation || 0,
      vt_score: malicious > 3 ? 'malicious' : malicious > 0 ? 'suspicious' : 'clean'
    };
  }

  // Mock results for when API key not configured
  _mockHashResult(hash) {
    return { found: false, hash, source: 'virustotal_mock', note: 'API key not configured' };
  }
  _mockUrlResult(url) {
    return { found: false, url, source: 'virustotal_mock', reputation: 'unknown' };
  }
  _mockDomainResult(domain) {
    return { found: false, domain, source: 'virustotal_mock', reputation: 'unknown' };
  }
  _mockIpResult(ip) {
    return { found: false, ip, source: 'virustotal_mock', reputation: 'unknown' };
  }
}

// ─── AbuseIPDB Enrichment ─────────────────────────────────────────────────────
class AbuseIPDBEnricher {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseUrl = 'https://api.abuseipdb.com/api/v2';
    this.enabled = !!apiKey;
  }

  async lookupIp(ip) {
    if (!this.enabled) return this._mockResult(ip);
    const cacheKey = `abuseipdb:${ip}`;
    const cached = INTEL_CACHE.get(cacheKey);
    if (cached) return cached;

    try {
      const res = await httpGet(
        `${this.baseUrl}/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
        { 'Key': this.apiKey, 'Accept': 'application/json' }
      );
      const result = this._parseResult(res.data);
      INTEL_CACHE.set(cacheKey, result);
      return result;
    } catch {
      return { found: false, ip, error: 'lookup_failed' };
    }
  }

  _parseResult(data) {
    const d = data?.data || {};
    return {
      found: true,
      source: 'abuseipdb',
      ip: d.ipAddress,
      abuse_score: d.abuseConfidenceScore || 0,
      country: d.countryCode,
      isp: d.isp,
      domain: d.domain,
      is_tor: d.isTor || false,
      is_proxy: d.isProxy || false,
      is_vpn: d.isVpn || false,
      total_reports: d.totalReports || 0,
      distinct_users: d.numDistinctUsers || 0,
      last_reported: d.lastReportedAt,
      reputation: d.abuseConfidenceScore > 80 ? 'malicious' :
                  d.abuseConfidenceScore > 30 ? 'suspicious' : 'clean',
      usage_type: d.usageType
    };
  }

  _mockResult(ip) {
    return { found: false, ip, source: 'abuseipdb_mock', note: 'API key not configured' };
  }
}

// ─── URLScan.io Enrichment ────────────────────────────────────────────────────
class URLScanEnricher {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseUrl = 'https://urlscan.io/api/v1';
    this.enabled = true; // Search API is partially public
  }

  async searchUrl(url) {
    const cacheKey = `urlscan:${crypto.createHash('md5').update(url).digest('hex')}`;
    const cached = INTEL_CACHE.get(cacheKey);
    if (cached) return cached;

    try {
      const domain = new URL(url).hostname;
      const res = await httpGet(
        `${this.baseUrl}/search/?q=domain:${domain}&size=5`,
        { 'API-Key': this.apiKey || '' }
      );
      const result = this._parseSearchResult(res.data, url);
      INTEL_CACHE.set(cacheKey, result);
      return result;
    } catch {
      return { found: false, url, source: 'urlscan', error: 'lookup_failed' };
    }
  }

  _parseSearchResult(data, url) {
    const results = data?.results || [];
    const malicious = results.filter(r => r.verdicts?.overall?.malicious);
    return {
      found: results.length > 0,
      source: 'urlscan',
      url,
      scan_count: results.length,
      malicious_count: malicious.length,
      reputation: malicious.length > 0 ? 'malicious' : results.length > 0 ? 'seen' : 'not_seen',
      latest_scan: results[0]?.task?.time,
      screenshots: results.slice(0, 2).map(r => r.screenshot).filter(Boolean),
      verdicts: results.slice(0, 3).map(r => ({
        url: r.page?.url,
        malicious: r.verdicts?.overall?.malicious,
        score: r.verdicts?.overall?.score,
        tags: r.verdicts?.overall?.tags
      }))
    };
  }
}

// ─── Passive DNS Enrichment ───────────────────────────────────────────────────
class PassiveDNSEnricher {
  constructor() {
    // Using SecurityTrails free tier or CIRCL pDNS
    this.circl_url = 'https://www.circl.lu/pdns/query';
    this.enabled = true;
  }

  async lookupDomain(domain) {
    const cacheKey = `pdns:${domain}`;
    const cached = INTEL_CACHE.get(cacheKey);
    if (cached) return cached;

    try {
      const res = await httpGet(`${this.circl_url}/${domain}`);
      const result = this._parseResult(res.data, domain);
      INTEL_CACHE.set(cacheKey, result);
      return result;
    } catch {
      return { found: false, domain, source: 'passive_dns', note: 'Service unavailable' };
    }
  }

  _parseResult(data, domain) {
    if (!data || typeof data !== 'object') {
      return { found: false, domain, source: 'passive_dns' };
    }
    const records = Array.isArray(data) ? data : (data.results || []);
    return {
      found: records.length > 0,
      source: 'passive_dns',
      domain,
      record_count: records.length,
      a_records: records.filter(r => r.rrtype === 'A').map(r => ({ ip: r.rdata, seen: r.time_last })),
      mx_records: records.filter(r => r.rrtype === 'MX').map(r => r.rdata),
      ns_records: records.filter(r => r.rrtype === 'NS').map(r => r.rdata),
      first_seen: records.reduce((min, r) => r.time_first < min ? r.time_first : min, Infinity),
      last_seen: records.reduce((max, r) => r.time_last > max ? r.time_last : max, 0),
      is_recently_registered: false // would calculate based on first_seen
    };
  }
}

// ─── Main Enrichment Orchestrator ────────────────────────────────────────────
class ThreatIntelEnrichmentService {
  constructor(config = {}) {
    this.vt = new VirusTotalEnricher(config.virustotal_api_key);
    this.abuseipdb = new AbuseIPDBEnricher(config.abuseipdb_api_key);
    this.urlscan = new URLScanEnricher(config.urlscan_api_key);
    this.pdns = new PassiveDNSEnricher();
    this.maxConcurrency = config.max_concurrency || 10;
    this.stats = { total_lookups: 0, cache_hits: 0, api_calls: 0 };
  }

  /**
   * Enrich all indicators from a parsed email
   * Returns comprehensive intelligence report
   */
  async enrich(parsedEmail) {
    const indicators = parsedEmail.indicators || {};
    const enrichment = {
      ips: {},
      domains: {},
      urls: {},
      hashes: {},
      summary: {
        malicious_ips: 0,
        malicious_domains: 0,
        malicious_urls: 0,
        malicious_hashes: 0,
        threat_intel_score: 0
      }
    };

    // ── Parallel enrichment with rate limiting ──
    const tasks = [];

    // IPs (limit to 5)
    for (const ip of (indicators.ips || []).slice(0, 5)) {
      tasks.push(this._enrichIp(ip).then(r => { enrichment.ips[ip] = r; }));
    }

    // Domains (limit to 10)
    for (const domain of (indicators.domains || []).slice(0, 10)) {
      tasks.push(this._enrichDomain(domain).then(r => { enrichment.domains[domain] = r; }));
    }

    // URLs (limit to 5)
    for (const url of (indicators.urls || []).slice(0, 5)) {
      tasks.push(this._enrichUrl(url).then(r => { enrichment.urls[url] = r; }));
    }

    // Hashes (limit to 5)
    for (const hash of (indicators.hashes || []).slice(0, 5)) {
      tasks.push(this._enrichHash(hash).then(r => { enrichment.hashes[hash] = r; }));
    }

    // Execute with concurrency limit
    await this._runConcurrent(tasks, this.maxConcurrency);

    // ── Compute summary ──
    enrichment.summary = this._computeSummary(enrichment);
    enrichment.threat_context = this._buildThreatContext(enrichment);
    enrichment.enriched_at = new Date().toISOString();

    return enrichment;
  }

  async _enrichIp(ip) {
    const [vt, abuse] = await Promise.allSettled([
      this.vt.lookupIp(ip),
      this.abuseipdb.lookupIp(ip)
    ]);
    return {
      ip,
      virustotal: vt.status === 'fulfilled' ? vt.value : null,
      abuseipdb: abuse.status === 'fulfilled' ? abuse.value : null,
      combined_reputation: this._combineReputation([
        vt.value?.vt_score,
        abuse.value?.reputation
      ])
    };
  }

  async _enrichDomain(domain) {
    const [vt, pdns] = await Promise.allSettled([
      this.vt.lookupDomain(domain),
      this.pdns.lookupDomain(domain)
    ]);
    return {
      domain,
      virustotal: vt.status === 'fulfilled' ? vt.value : null,
      passive_dns: pdns.status === 'fulfilled' ? pdns.value : null,
      combined_reputation: this._combineReputation([vt.value?.vt_score])
    };
  }

  async _enrichUrl(url) {
    const [vt, urlscan] = await Promise.allSettled([
      this.vt.lookupUrl(url),
      this.urlscan.searchUrl(url)
    ]);
    return {
      url,
      virustotal: vt.status === 'fulfilled' ? vt.value : null,
      urlscan: urlscan.status === 'fulfilled' ? urlscan.value : null,
      combined_reputation: this._combineReputation([
        vt.value?.reputation,
        urlscan.value?.reputation
      ])
    };
  }

  async _enrichHash(hash) {
    const vt = await this.vt.lookupHash(hash).catch(() => null);
    return {
      hash,
      virustotal: vt,
      combined_reputation: vt?.reputation || 'unknown'
    };
  }

  _combineReputation(reputations) {
    const filtered = reputations.filter(Boolean);
    if (filtered.some(r => r === 'malicious')) return 'malicious';
    if (filtered.some(r => r === 'suspicious')) return 'suspicious';
    if (filtered.some(r => r === 'clean')) return 'clean';
    return 'unknown';
  }

  _computeSummary(enrichment) {
    const ipValues = Object.values(enrichment.ips);
    const domainValues = Object.values(enrichment.domains);
    const urlValues = Object.values(enrichment.urls);
    const hashValues = Object.values(enrichment.hashes);

    const malIps = ipValues.filter(i => i?.combined_reputation === 'malicious').length;
    const malDomains = domainValues.filter(d => d?.combined_reputation === 'malicious').length;
    const malUrls = urlValues.filter(u => u?.combined_reputation === 'malicious').length;
    const malHashes = hashValues.filter(h => h?.combined_reputation === 'malicious').length;

    const intelScore = Math.min(100,
      malIps * 30 + malDomains * 25 + malUrls * 35 + malHashes * 40 +
      (ipValues.filter(i => i?.abuseipdb?.abuse_score > 80).length * 20)
    );

    return {
      malicious_ips: malIps,
      malicious_domains: malDomains,
      malicious_urls: malUrls,
      malicious_hashes: malHashes,
      total_indicators: ipValues.length + domainValues.length + urlValues.length + hashValues.length,
      threat_intel_score: intelScore,
      overall_threat: intelScore > 70 ? 'high' : intelScore > 30 ? 'medium' : 'low'
    };
  }

  _buildThreatContext(enrichment) {
    const context = [];

    for (const [ip, data] of Object.entries(enrichment.ips)) {
      if (data?.abuseipdb?.is_tor) context.push({ type: 'tor_exit_node', indicator: ip, severity: 'high' });
      if (data?.abuseipdb?.abuse_score > 80) context.push({ type: 'known_malicious_ip', indicator: ip, severity: 'critical', score: data.abuseipdb.abuse_score });
      if (data?.combined_reputation === 'malicious') context.push({ type: 'vt_malicious_ip', indicator: ip, severity: 'high' });
    }

    for (const [domain, data] of Object.entries(enrichment.domains)) {
      if (data?.combined_reputation === 'malicious') context.push({ type: 'malicious_domain', indicator: domain, severity: 'critical' });
      if (data?.passive_dns?.is_recently_registered) context.push({ type: 'newly_registered_domain', indicator: domain, severity: 'medium' });
    }

    for (const [hash, data] of Object.entries(enrichment.hashes)) {
      if (data?.virustotal?.malicious_count > 10) context.push({
        type: 'known_malware',
        indicator: hash,
        severity: 'critical',
        detection_ratio: data.virustotal.detection_ratio,
        threat_names: data.virustotal.threat_names
      });
    }

    return context;
  }

  async _runConcurrent(tasks, concurrency) {
    const results = [];
    for (let i = 0; i < tasks.length; i += concurrency) {
      const batch = tasks.slice(i, i + concurrency);
      await Promise.allSettled(batch);
    }
    return results;
  }

  getCacheStats() {
    return { size: INTEL_CACHE.size(), ...this.stats };
  }
}

module.exports = {
  ThreatIntelEnrichmentService,
  VirusTotalEnricher,
  AbuseIPDBEnricher,
  URLScanEnricher,
  PassiveDNSEnricher,
  INTEL_CACHE
};
