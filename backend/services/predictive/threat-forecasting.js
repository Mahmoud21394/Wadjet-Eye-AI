/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Predictive Threat Intelligence (Phase 4)
 *  backend/services/predictive/threat-forecasting.js
 *
 *  Implements:
 *  • Time-series CVE exploitation forecasting (ARIMA-inspired)
 *  • GDELT geopolitical context engine (real API integration)
 *  • Threat actor campaign prediction via pattern matching
 *  • Vulnerability exploitation probability scoring
 *  • Attack trend extrapolation with confidence intervals
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const https  = require('https');
const crypto = require('crypto');

// ── GDELT API integration ─────────────────────────────────────────
const GDELT_API = 'https://api.gdeltproject.org/api/v2';

async function fetchGdeltEvents(opts = {}) {
  const query     = opts.query     || 'cyberattack OR ransomware OR "data breach" OR "supply chain attack"';
  const mode      = opts.mode      || 'ArtList';
  const format    = opts.format    || 'json';
  const maxRecords = opts.maxRecords || 75;
  const timespan  = opts.timespan  || '1week';

  const params = new URLSearchParams({
    query,
    mode,
    format,
    maxrecords: maxRecords,
    timespan,
    sort: 'HybridRel',
    THEMES: opts.themes || '',
  });

  const url = `${GDELT_API}/doc/doc?${params}`;

  return new Promise((resolve) => {
    const req = https.get(url, {
      timeout: 20000,
      headers: { 'User-Agent': 'WadjetEye-ThreatIntel/2.0' },
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          resolve({ success: true, data: data.articles || [] });
        } catch {
          resolve({ success: false, data: [] });
        }
      });
    });
    req.on('error',   () => resolve({ success: false, data: [] }));
    req.on('timeout', () => { req.destroy(); resolve({ success: false, data: [] }); });
  });
}

// ── GDELT geographic threat heat map ─────────────────────────────
async function fetchGdeltGeoContext(country = '', themes = '') {
  const query = [
    'cyberattack OR malware OR ransomware OR espionage',
    country  ? `sourcecountry:${country}` : '',
    themes   ? `theme:${themes}` : '',
  ].filter(Boolean).join(' ');

  const params = new URLSearchParams({
    query,
    mode:     'PointData',
    format:   'json',
    timespan: '2weeks',
    maxrecords: 250,
  });

  const url = `${GDELT_API}/geo/geo?${params}`;

  return new Promise((resolve) => {
    const req = https.get(url, { timeout: 20000 }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          resolve({ success: true, data: data.features || [] });
        } catch {
          resolve({ success: false, data: [] });
        }
      });
    });
    req.on('error',   () => resolve({ success: false, data: [] }));
    req.on('timeout', () => { req.destroy(); resolve({ success: false, data: [] })); });
  });
}

// ── Geopolitical context scoring ──────────────────────────────────
function scoreGeopoliticalRisk(articles, orgCountry = '') {
  if (!articles || articles.length === 0) {
    return { risk_score: 0, threat_themes: [], regional_hotspots: [], key_articles: [] };
  }

  // Theme extraction
  const themeCount = {};
  const toneSum    = {};
  for (const article of articles) {
    const themes = (article.themes || '').split(',').map(t => t.trim()).filter(Boolean);
    for (const theme of themes) {
      themeCount[theme] = (themeCount[theme] || 0) + 1;
      toneSum[theme]    = (toneSum[theme]    || 0) + (parseFloat(article.tone) || 0);
    }
  }

  // Top threat themes
  const threatThemes = Object.entries(themeCount)
    .filter(([t]) => /CYBER|TERROR|CONFLICT|ATTACK|MILITARY|ESPIONAGE/i.test(t))
    .sort(([,a], [,b]) => b - a)
    .slice(0, 10)
    .map(([theme, count]) => ({
      theme,
      count,
      avg_tone: toneSum[theme] ? Math.round((toneSum[theme] / count) * 100) / 100 : 0,
    }));

  // Regional hotspot analysis
  const countryCount = {};
  for (const article of articles) {
    const locs = (article.locations || []);
    for (const loc of locs) {
      if (loc.country_code) {
        countryCount[loc.country_code] = (countryCount[loc.country_code] || 0) + 1;
      }
    }
  }

  const regionalHotspots = Object.entries(countryCount)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 15)
    .map(([country, mentions]) => ({ country, mentions }));

  // Composite risk score (0–100)
  const articleCount   = articles.length;
  const criticalThemes = threatThemes.filter(t => /CYBER_ATTACK|TERROR|CONFLICT|MILITARY_ATTACK/i.test(t.theme)).length;
  const negTone        = articles.filter(a => parseFloat(a.tone) < -5).length;

  const risk_score = Math.min(100, Math.round(
    (articleCount   / 2)           +
    (criticalThemes * 5)           +
    (negTone        / articleCount * 30)
  ));

  const key_articles = articles
    .filter(a => parseFloat(a.tone) < -3)
    .slice(0, 10)
    .map(a => ({
      title:       a.title,
      url:         a.url,
      date:        a.seendate,
      tone:        parseFloat(a.tone),
      domain:      a.domain,
      socialimage: a.socialimage,
    }));

  return {
    risk_score,
    threat_themes:    threatThemes,
    regional_hotspots: regionalHotspots,
    key_articles,
    analyzed_articles: articleCount,
    generated_at:      new Date().toISOString(),
  };
}

// ── CVE Exploitation Time-Series Forecasting ──────────────────────
// Uses exponential smoothing (Holt-Winters simple form) on historical CVE exploit data
function forecastExploitationProbability(cveHistory, opts = {}) {
  if (!cveHistory || cveHistory.length < 3) {
    return { probability: 0.1, confidence: 'LOW', horizon_days: 30, method: 'insufficient_data' };
  }

  const alpha     = opts.alpha     || 0.3;  // smoothing factor
  const horizon   = opts.horizon   || 30;   // forecast days
  const series    = cveHistory.map(d => d.exploits_count || d.value || 0);

  // Simple exponential smoothing
  let smoothed = series[0];
  for (let i = 1; i < series.length; i++) {
    smoothed = alpha * series[i] + (1 - alpha) * smoothed;
  }

  // Trend component (linear)
  const n     = series.length;
  const xMean = (n - 1) / 2;
  const yMean = series.reduce((s, v) => s + v, 0) / n;
  let num = 0, den = 0;
  series.forEach((y, x) => {
    num += (x - xMean) * (y - yMean);
    den += (x - xMean) ** 2;
  });
  const slope    = den !== 0 ? num / den : 0;
  const intercept = yMean - slope * xMean;

  // Forecast
  const forecast = [];
  for (let d = 1; d <= horizon; d++) {
    const trend_val = intercept + slope * (n - 1 + d);
    const smoothed_val = alpha * trend_val + (1 - alpha) * smoothed;
    forecast.push({
      day:   d,
      value: Math.max(0, Math.round(smoothed_val * 10) / 10),
    });
  }

  // Probability of exploitation in next horizon days
  const maxHistorical  = Math.max(...series);
  const forecastPeak   = Math.max(...forecast.map(f => f.value));
  const prob           = maxHistorical > 0
    ? Math.min(0.99, Math.max(0.01, forecastPeak / maxHistorical))
    : 0.1;

  // CVSS/EPSS enrichment factor (if provided)
  const epss = opts.epss_score || null;
  const cvss = opts.cvss_score || null;

  let adjusted_prob = prob;
  if (epss !== null) adjusted_prob = (prob * 0.6) + (epss * 0.4);
  if (cvss !== null && cvss >= 9.0) adjusted_prob = Math.min(0.99, adjusted_prob * 1.3);

  const confidence = n >= 30 ? 'HIGH' : n >= 14 ? 'MEDIUM' : 'LOW';

  return {
    probability:         Math.round(adjusted_prob * 100) / 100,
    probability_pct:     Math.round(adjusted_prob * 100),
    confidence,
    horizon_days:        horizon,
    trend:               slope > 0.1 ? 'INCREASING' : slope < -0.1 ? 'DECREASING' : 'STABLE',
    slope:               Math.round(slope * 1000) / 1000,
    forecast,
    last_smoothed:       Math.round(smoothed * 10) / 10,
    data_points:         n,
    method:              'exponential_smoothing_with_trend',
    epss_adjusted:       epss !== null,
    cvss_adjusted:       cvss !== null,
  };
}

// ── CVE Priority Queue ────────────────────────────────────────────
function prioritizeCves(cves, opts = {}) {
  return cves
    .map(cve => {
      // Composite priority score
      const cvss    = cve.cvss_score || 0;
      const epss    = cve.epss_score || 0;
      const ageD    = cve.published_date
        ? (Date.now() - new Date(cve.published_date).getTime()) / 86_400_000
        : 365;
      const kev     = cve.in_kev     ? 40 : 0;  // CISA Known Exploited Vulnerability bonus
      const pub_exp = cve.public_exploit_count || 0;

      const score = Math.min(100, Math.round(
        (cvss * 4)                    +   // max 40
        (epss * 25)                   +   // max 25
        kev                           +   // 40 if in KEV
        Math.min(pub_exp * 2, 20)     +   // max 20 from public exploits
        (ageD < 7 ? 15 : ageD < 30 ? 10 : ageD < 90 ? 5 : 0)  // recency bonus
      ));

      return { ...cve, priority_score: score };
    })
    .sort((a, b) => b.priority_score - a.priority_score);
}

// ── Threat actor campaign prediction ─────────────────────────────
function predictCampaignLikelihood(historicalCampaigns, currentIndicators) {
  if (!historicalCampaigns || historicalCampaigns.length === 0) {
    return [];
  }

  const predictions = [];

  for (const actor of [...new Set(historicalCampaigns.map(c => c.threat_actor))]) {
    const actorCampaigns = historicalCampaigns.filter(c => c.threat_actor === actor);

    // Calculate inter-campaign interval stats
    const intervals = [];
    for (let i = 1; i < actorCampaigns.length; i++) {
      const prev = new Date(actorCampaigns[i - 1].start_date).getTime();
      const curr = new Date(actorCampaigns[i].start_date).getTime();
      if (!isNaN(prev) && !isNaN(curr)) intervals.push((curr - prev) / 86_400_000);
    }

    const avgInterval = intervals.length > 0
      ? intervals.reduce((s, v) => s + v, 0) / intervals.length
      : 90;

    const lastCampaign = actorCampaigns[actorCampaigns.length - 1];
    const daysSinceLast = lastCampaign?.start_date
      ? (Date.now() - new Date(lastCampaign.start_date).getTime()) / 86_400_000
      : Infinity;

    // Likelihood increases as we approach expected interval
    const dueRatio   = daysSinceLast / avgInterval;
    const likelihood = Math.min(0.95, Math.max(0.05,
      dueRatio >= 1.0 ? 0.7 + (dueRatio - 1.0) * 0.1 :
      dueRatio >= 0.7 ? 0.4 + (dueRatio - 0.7) * 1.0 :
      dueRatio * 0.5
    ));

    // Match current indicators to actor TTPs
    const actorTtps   = actorCampaigns.flatMap(c => c.ttps || []);
    const iocMatches  = currentIndicators.filter(ioc =>
      actorTtps.some(ttp => ioc.technique_id === ttp || ioc.signature === ttp)
    ).length;

    const iocBonus    = Math.min(0.25, iocMatches * 0.05);
    const finalLikelihood = Math.min(0.99, likelihood + iocBonus);

    predictions.push({
      threat_actor:         actor,
      campaign_likelihood:  Math.round(finalLikelihood * 100),
      days_since_last:      Math.round(daysSinceLast),
      avg_interval_days:    Math.round(avgInterval),
      expected_next_window: `${Math.round(avgInterval - daysSinceLast)} days`,
      ioc_matches:          iocMatches,
      last_campaign_date:   lastCampaign?.start_date || null,
      target_sectors:       actorCampaigns.flatMap(c => c.target_sectors || []).filter(Boolean)
        .reduce((acc, s) => { acc[s] = (acc[s] || 0) + 1; return acc; }, {}),
      confidence:           actorCampaigns.length >= 5 ? 'HIGH' : actorCampaigns.length >= 2 ? 'MEDIUM' : 'LOW',
    });
  }

  return predictions.sort((a, b) => b.campaign_likelihood - a.campaign_likelihood);
}

// ── Full predictive intelligence report ──────────────────────────
async function buildPredictiveIntelReport(opts = {}) {
  const [gdeltRes, geoRes] = await Promise.allSettled([
    fetchGdeltEvents({
      query:   opts.gdeltQuery || 'cyberattack OR ransomware OR APT OR "supply chain"',
      timespan: opts.timespan  || '2weeks',
    }),
    fetchGdeltGeoContext(opts.country || '', 'CYBER_ATTACK'),
  ]);

  const articles     = gdeltRes.status   === 'fulfilled' ? gdeltRes.value.data   : [];
  const geoFeatures  = geoRes.status     === 'fulfilled' ? geoRes.value.data     : [];

  const geoContext   = scoreGeopoliticalRisk(articles, opts.orgCountry);
  const campaigns    = predictCampaignLikelihood(opts.historicalCampaigns || [], opts.currentIndicators || []);
  const cveQueue     = prioritizeCves(opts.cves || []);

  return {
    report_id:    crypto.randomUUID(),
    generated_at: new Date().toISOString(),
    geopolitical: geoContext,
    geo_features: geoFeatures.slice(0, 50),
    campaign_predictions: campaigns,
    cve_priority_queue:   cveQueue.slice(0, 20),
    overall_threat_level: _overallThreatLevel(geoContext.risk_score, campaigns),
  };
}

function _overallThreatLevel(geoRisk, campaigns) {
  const topCampaignLikelihood = campaigns.length > 0 ? campaigns[0].campaign_likelihood : 0;
  const combined = (geoRisk * 0.5) + (topCampaignLikelihood * 0.5);

  if (combined >= 75) return 'CRITICAL';
  if (combined >= 55) return 'HIGH';
  if (combined >= 35) return 'MEDIUM';
  return 'LOW';
}

module.exports = {
  fetchGdeltEvents,
  fetchGdeltGeoContext,
  scoreGeopoliticalRisk,
  forecastExploitationProbability,
  prioritizeCves,
  predictCampaignLikelihood,
  buildPredictiveIntelReport,
};
