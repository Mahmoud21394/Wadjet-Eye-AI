/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — GDELT Threat Intelligence Connector (Phase 4)
 *  backend/services/integrations/gdelt-intel.js
 *
 *  Queries GDELT 2.0 APIs for:
 *  • Real-time geopolitical event feeds relevant to cyber threats
 *  • Threat actor news monitoring via GDELT DocAPI
 *  • Country-level threat landscape from GDELT GKG (Global Knowledge Graph)
 *  • Predictive threat indicators via sentiment + event correlation
 *
 *  GDELT APIs used:
 *  • DOC API: https://api.gdeltproject.org/api/v2/doc/doc
 *  • GKG API:  https://api.gdeltproject.org/api/v2/gkg/gkg
 *  • TV API:   https://api.gdeltproject.org/api/v2/tv/tv (broadcast intel)
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const https  = require('https');
const crypto = require('crypto');

// ── Configuration ─────────────────────────────────────────────────
const GDELT_DOC_URL = 'https://api.gdeltproject.org/api/v2/doc/doc';
const GDELT_GKG_URL = 'https://api.gdeltproject.org/api/v2/gkg/gkg';
const GDELT_TV_URL  = 'https://api.gdeltproject.org/api/v2/tv/tv';

// Max articles per query (GDELT free tier = 250)
const MAX_RECORDS = parseInt(process.env.GDELT_MAX_RECORDS || '250', 10);

// Cache TTL for GDELT responses (15 min — GDELT updates every 15 min)
const CACHE_TTL_MS = 15 * 60 * 1000;
const _cache = new Map();

// ── HTTP helper ───────────────────────────────────────────────────
function gdeltGet(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        try {
          resolve(JSON.parse(text));
        } catch (_) {
          resolve({ raw: text });
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('GDELT request timeout')); });
  });
}

function getCached(key) {
  const entry = _cache.get(key);
  if (entry && Date.now() < entry.expiresAt) return entry.value;
  _cache.delete(key);
  return null;
}

function setCache(key, value) {
  _cache.set(key, { value, expiresAt: Date.now() + CACHE_TTL_MS });
}

// ── Cyber-threat relevant GDELT themes ───────────────────────────
const CYBER_THEMES = [
  'CYBER_ATTACK', 'CYBER_ESPIONAGE', 'CYBER_CRIME', 'CYBER_WARFARE',
  'HACKING', 'RANSOMWARE', 'DATA_BREACH', 'PHISHING',
  'CRITICAL_INFRASTRUCTURE', 'SUPPLY_CHAIN_ATTACK',
];

// Threat-actor related search terms
const THREAT_ACTOR_KEYWORDS = [
  'APT28', 'APT29', 'Cozy Bear', 'Fancy Bear', 'Lazarus Group',
  'Sandworm', 'APT41', 'Volt Typhoon', 'Salt Typhoon', 'FIN7',
  'LockBit', 'REvil', 'Conti', 'BlackCat', 'ALPHV',
  'zero day', 'zero-day', 'critical vulnerability', 'exploit kit',
  'ransomware attack', 'cyber espionage', 'nation state attack',
  'supply chain compromise',
];

// ── Core query functions ──────────────────────────────────────────

/**
 * searchDocApi — query GDELT Doc API for relevant articles
 * @param {object} params
 * @param {string} params.query       - Search query (Boolean operators supported)
 * @param {string} params.mode        - 'artlist' | 'timeline' | 'timelinevolume'
 * @param {number} params.maxRecords  - Max articles (default 250)
 * @param {string} params.startdatetime - YYYYMMDDHHMMSS format
 * @param {string} params.enddatetime
 * @param {string} params.sort        - 'DateDesc' | 'ToneDesc' | 'Relevance'
 * @param {string} params.sourcelang  - 'english' | 'arabic' | etc.
 * @param {string[]} params.themes    - Filter by GDELT themes
 */
async function searchDocApi(params = {}) {
  const query = buildDocQuery(params);
  const cacheKey = `doc:${crypto.createHash('md5').update(query).digest('hex')}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  const url = `${GDELT_DOC_URL}?${query}&format=json`;
  const result = await gdeltGet(url);
  setCache(cacheKey, result);
  return result;
}

function buildDocQuery(params) {
  const p = new URLSearchParams();
  p.set('query',      params.query || 'cyber attack');
  p.set('mode',       params.mode  || 'artlist');
  p.set('maxrecords', String(params.maxRecords || MAX_RECORDS));
  p.set('sort',       params.sort  || 'DateDesc');
  if (params.sourcelang) p.set('sourcelang', params.sourcelang);
  if (params.startdatetime) p.set('startdatetime', params.startdatetime);
  if (params.enddatetime)   p.set('enddatetime', params.enddatetime);
  if (params.themes?.length) p.set('theme', params.themes.join(','));
  return p.toString();
}

/**
 * searchGKG — query GDELT Global Knowledge Graph for entities
 * @param {object} params
 * @param {string} params.query    - Theme or keyword query
 * @param {string} params.mode     - 'artlist' | 'timelinelang' | 'tonechart'
 */
async function searchGKG(params = {}) {
  const p = new URLSearchParams({
    query:      params.query || 'cybersecurity',
    mode:       params.mode  || 'artlist',
    maxrecords: String(Math.min(params.maxRecords || 250, 250)),
    sort:       params.sort  || 'DateDesc',
    format:     'json',
  });

  const cacheKey = `gkg:${crypto.createHash('md5').update(p.toString()).digest('hex')}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  const url = `${GDELT_GKG_URL}?${p.toString()}`;
  const result = await gdeltGet(url);
  setCache(cacheKey, result);
  return result;
}

// ── Threat intelligence feeds ─────────────────────────────────────

/**
 * getCyberThreatNews — fetch recent cyber threat news articles
 * @param {object} opts
 * @param {number} opts.hours     - Look-back window (default 24h)
 * @param {string} opts.language  - Source language filter (default 'english')
 * @param {string[]} opts.actors  - Optional threat actor filter
 */
async function getCyberThreatNews(opts = {}) {
  const hoursBack = opts.hours || 24;
  const now = new Date();
  const startDate = new Date(now.getTime() - hoursBack * 3600000);

  const queryTerms = [
    '(cybersecurity OR "cyber attack" OR ransomware OR malware OR "data breach")',
    ...(opts.actors ? [`("${opts.actors.join('" OR "')}")`] : []),
  ].join(' AND ');

  try {
    const result = await searchDocApi({
      query:    queryTerms,
      mode:     'artlist',
      sort:     'DateDesc',
      sourcelang: opts.language || 'english',
      startdatetime: formatGDELTDate(startDate),
      enddatetime:   formatGDELTDate(now),
    });

    const articles = result.articles || [];
    return {
      success:  true,
      source:   'gdelt_doc',
      query:    queryTerms,
      count:    articles.length,
      articles: articles.map(normalizeArticle),
      fetched_at: now.toISOString(),
    };
  } catch (err) {
    console.error('[GDELT] getCyberThreatNews error:', err.message);
    return { success: false, error: err.message, articles: [] };
  }
}

/**
 * getThreatActorMentions — monitor named threat actor mentions
 * @param {string[]} actorNames - Threat actor names to monitor
 * @param {number}   hours      - Look-back window
 */
async function getThreatActorMentions(actorNames = THREAT_ACTOR_KEYWORDS.slice(0, 5), hours = 48) {
  const now = new Date();
  const startDate = new Date(now.getTime() - hours * 3600000);

  const query = `("${actorNames.join('" OR "')}")`;

  try {
    const result = await searchDocApi({
      query,
      mode:          'artlist',
      sort:          'DateDesc',
      startdatetime: formatGDELTDate(startDate),
      enddatetime:   formatGDELTDate(now),
      maxRecords:    100,
    });

    const articles = result.articles || [];

    // Group by actor name detected in title/content
    const byActor = {};
    for (const article of articles) {
      const detected = actorNames.filter(actor =>
        (article.title + ' ' + (article.url || '')).toLowerCase()
          .includes(actor.toLowerCase())
      );
      for (const actor of detected) {
        if (!byActor[actor]) byActor[actor] = [];
        byActor[actor].push(normalizeArticle(article));
      }
    }

    return {
      success:     true,
      total:       articles.length,
      by_actor:    byActor,
      actors_found: Object.keys(byActor),
      fetched_at:  now.toISOString(),
    };
  } catch (err) {
    console.error('[GDELT] getThreatActorMentions error:', err.message);
    return { success: false, error: err.message, by_actor: {} };
  }
}

/**
 * getGeopoliticalRisk — assess geopolitical risk for target countries
 * Uses GDELT CAMEO event codes for conflict/instability events
 * @param {string[]} countries - ISO2 country codes
 * @param {number}   days      - Look-back window
 */
async function getGeopoliticalRisk(countries = [], days = 7) {
  const now = new Date();
  const startDate = new Date(now.getTime() - days * 24 * 3600000);

  const countryFilter = countries.length > 0
    ? `(${countries.map(c => `location:"${c}"`).join(' OR ')})`
    : '';
  const query = `(cybersecurity OR "critical infrastructure" OR "state sponsored") ${countryFilter}`.trim();

  try {
    const result = await searchGKG({
      query,
      mode:      'tonechart',
      startdatetime: formatGDELTDate(startDate),
      enddatetime:   formatGDELTDate(now),
    });

    // Parse tone chart for sentiment analysis
    const toneData = result.tonechart || [];
    const avgTone = toneData.length > 0
      ? toneData.reduce((sum, t) => sum + parseFloat(t.avgtone || 0), 0) / toneData.length
      : 0;

    return {
      success:      true,
      countries,
      avg_tone:     Math.round(avgTone * 100) / 100,
      risk_level:   toneToRiskLevel(avgTone),
      risk_score:   Math.min(100, Math.round(Math.abs(avgTone) * 5)),
      tone_chart:   toneData,
      period_days:  days,
      fetched_at:   now.toISOString(),
    };
  } catch (err) {
    console.error('[GDELT] getGeopoliticalRisk error:', err.message);
    return { success: false, error: err.message, risk_level: 'unknown' };
  }
}

/**
 * getVulnerabilityBuzz — detect CVE/vulnerability buzz spikes
 * Surge in GDELT mentions of specific CVEs may indicate active exploitation
 */
async function getVulnerabilityBuzz(cveIds = [], hours = 72) {
  if (!cveIds || cveIds.length === 0) {
    // Fetch trending vulnerability discussion
    cveIds = ['CVE', 'zero-day', 'exploit', 'critical vulnerability'];
  }

  const query = `(${cveIds.map(id => `"${id}"`).join(' OR ')})`;
  const now = new Date();
  const startDate = new Date(now.getTime() - hours * 3600000);

  try {
    // Use timelinevolume to detect mention spikes
    const volumeResult = await searchDocApi({
      query,
      mode:          'timelinevolume',
      startdatetime: formatGDELTDate(startDate),
      enddatetime:   formatGDELTDate(now),
    });

    // Also get article list
    const artResult = await searchDocApi({
      query,
      mode:      'artlist',
      sort:      'DateDesc',
      maxRecords: 50,
      startdatetime: formatGDELTDate(startDate),
      enddatetime:   formatGDELTDate(now),
    });

    const timeline = volumeResult.timeline || [];
    const articles = (artResult.articles || []).map(normalizeArticle);

    // Detect volume spike (last period vs average)
    const volumes = timeline.map(t => parseFloat(t.value || 0));
    const avgVolume = volumes.length > 0 ? volumes.reduce((a, b) => a + b, 0) / volumes.length : 0;
    const lastVolume = volumes[volumes.length - 1] || 0;
    const spikeRatio = avgVolume > 0 ? lastVolume / avgVolume : 1;

    return {
      success:       true,
      cve_queries:   cveIds,
      spike_ratio:   Math.round(spikeRatio * 100) / 100,
      spike_detected: spikeRatio > 2.0,      // 2× normal volume = spike
      avg_volume:    avgVolume,
      current_volume: lastVolume,
      timeline,
      top_articles:  articles.slice(0, 20),
      fetched_at:    now.toISOString(),
    };
  } catch (err) {
    console.error('[GDELT] getVulnerabilityBuzz error:', err.message);
    return { success: false, error: err.message };
  }
}

/**
 * getIntelDigest — comprehensive intel digest for SOC morning briefing
 * Combines cyber news, threat actor mentions, geo risk
 */
async function getIntelDigest(opts = {}) {
  const [news, actors, geoRisk] = await Promise.allSettled([
    getCyberThreatNews({ hours: opts.hours || 24, language: 'english' }),
    getThreatActorMentions(THREAT_ACTOR_KEYWORDS.slice(0, 10), opts.hours || 24),
    getGeopoliticalRisk(opts.countries || [], opts.days || 3),
  ]);

  return {
    timestamp:   new Date().toISOString(),
    cyber_news:  news.status === 'fulfilled' ? news.value : { success: false, error: news.reason?.message },
    threat_actors: actors.status === 'fulfilled' ? actors.value : { success: false, error: actors.reason?.message },
    geo_risk:    geoRisk.status === 'fulfilled' ? geoRisk.value : { success: false, error: geoRisk.reason?.message },
    source:      'gdelt',
  };
}

// ── Helpers ───────────────────────────────────────────────────────

function formatGDELTDate(date) {
  return date.toISOString()
    .replace(/[-:T]/g, '')
    .substring(0, 14);
}

function toneToRiskLevel(tone) {
  if (tone < -5)  return 'critical';
  if (tone < -2)  return 'high';
  if (tone < 0)   return 'medium';
  if (tone < 2)   return 'low';
  return 'minimal';
}

function normalizeArticle(article) {
  return {
    url:        article.url || '',
    title:      article.title || '',
    seendate:   article.seendate || null,
    domain:     article.domain || '',
    language:   article.language || '',
    sourcecountry: article.sourcecountry || '',
    tone:       parseFloat(article.tone || 0),
    relevance:  parseFloat(article.relevance || 0),
  };
}

module.exports = {
  searchDocApi,
  searchGKG,
  getCyberThreatNews,
  getThreatActorMentions,
  getGeopoliticalRisk,
  getVulnerabilityBuzz,
  getIntelDigest,
  CYBER_THEMES,
  THREAT_ACTOR_KEYWORDS,
};
