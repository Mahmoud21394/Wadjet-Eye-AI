/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Cyber News RSS Ingestion Service v5.2
 *  backend/services/news-ingestion.js
 *
 *  Ingests cyber threat news from:
 *    - The Hacker News    (thehackernews.com)
 *    - BleepingComputer   (bleepingcomputer.com)
 *    - SecurityWeek       (securityweek.com)
 *    - Krebs on Security  (krebsonsecurity.com)
 *    - CISA Alerts        (us-cert.cisa.gov)
 *    - Dark Reading       (darkreading.com)
 *
 *  Extracts: actors, malware families, CVEs, campaigns
 *  Stores in: news_articles table + cross-refs to threat actors
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const axios      = require('axios');
const { supabase } = require('../config/supabase');

const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';

// ── Known threat actor aliases (for NLP extraction) ───────────
const KNOWN_ACTORS = [
  'APT1','APT2','APT3','APT4','APT10','APT17','APT18','APT19',
  'APT28','APT29','APT30','APT31','APT32','APT33','APT34','APT35',
  'APT37','APT38','APT40','APT41',
  'Lazarus Group','Lazarus','ZINC',
  'Cozy Bear','Fancy Bear','Sandworm','Turla',
  'FIN7','FIN8','FIN6','FIN4',
  'Charming Kitten','Phosphorus','TA453',
  'Lapsus$','Scattered Spider','UNC3944',
  'REvil','Conti','LockBit','BlackCat','ALPHV','Hive',
  'MuddyWater','Kimsuky','SideWinder','Equation Group',
  'Volt Typhoon','Salt Typhoon','Flax Typhoon',
];

// ── Known malware families ─────────────────────────────────────
const KNOWN_MALWARE = [
  'Cobalt Strike','Mimikatz','Metasploit','AsyncRAT','QuasarRAT',
  'njRAT','DarkComet','Agent Tesla','RedLine','Vidar','Raccoon',
  'IcedID','BazarLoader','TrickBot','Emotet','Qakbot','Dridex',
  'Ryuk','REvil','LockBit','BlackCat','Conti','Hive','Cl0p',
  'WannaCry','NotPetya','Petya','BlackEnergy','Industroyer',
  'PlugX','ShadowPad','Gh0stRAT','FinFisher','Pegasus',
  'Stuxnet','Flame','Duqu','RedEcho','Sunburst','Solorigate',
];

// ── RSS feed definitions ───────────────────────────────────────
const RSS_FEEDS = [
  {
    name:      'The Hacker News',
    url:       'https://feeds.feedburner.com/TheHackersNews',
    category:  'threat-intel',
  },
  {
    name:      'BleepingComputer',
    url:       'https://www.bleepingcomputer.com/feed/',
    category:  'security-news',
  },
  {
    name:      'SecurityWeek',
    url:       'https://feeds.feedburner.com/securityweek',
    category:  'security-news',
  },
  {
    name:      'Krebs on Security',
    url:       'https://krebsonsecurity.com/feed/',
    category:  'investigation',
  },
  {
    name:      'CISA Alerts',
    url:       'https://www.cisa.gov/cybersecurity-advisories/all.xml',
    category:  'government-advisory',
  },
  {
    name:      'Dark Reading',
    url:       'https://www.darkreading.com/rss.xml',
    category:  'security-news',
  },
  {
    name:      'Threat Post',
    url:       'https://threatpost.com/feed/',
    category:  'threat-intel',
  },
];

// ── Simple RSS XML parser (no dependencies) ─────────────────
function parseRSS(xmlText) {
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let match;

  while ((match = itemRegex.exec(xmlText)) !== null) {
    const block = match[1];

    const getTag = (tag) => {
      const m = block.match(new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tag}>|<${tag}[^>]*>([^<]*)<\\/${tag}>`));
      if (!m) return '';
      return (m[1] || m[2] || '').trim();
    };

    const title       = getTag('title');
    const link        = getTag('link') || block.match(/<link>([^<]+)<\/link>/)?.[1] || '';
    const description = getTag('description');
    const pubDate     = getTag('pubDate');
    const guid        = getTag('guid') || link;

    if (title && link) {
      items.push({ title, link: link.trim(), description, pubDate, guid });
    }
  }
  return items;
}

// ── Extract entities from text ─────────────────────────────
function extractEntities(text) {
  const upperText = text.toUpperCase();

  // CVEs
  const cvePattern = /CVE-\d{4}-\d{4,7}/gi;
  const cves = [...new Set((text.match(cvePattern) || []).map(c => c.toUpperCase()))].slice(0, 10);

  // Threat actors
  const actors = KNOWN_ACTORS.filter(a =>
    text.toLowerCase().includes(a.toLowerCase())
  ).slice(0, 5);

  // Malware
  const malware = KNOWN_MALWARE.filter(m =>
    text.toLowerCase().includes(m.toLowerCase())
  ).slice(0, 5);

  // Severity inference from keywords
  let severity = 'medium';
  if (/critical|zero.?day|actively exploit|in the wild|ransomware|nation.?state/i.test(text)) severity = 'critical';
  else if (/high.sever|data breach|supply chain|backdoor|rce|remote code/i.test(text)) severity = 'high';
  else if (/patch|update|advisory|vulnerability|cve/i.test(text)) severity = 'medium';
  else severity = 'low';

  // Categories
  const tags = [];
  if (/ransomware/i.test(text))          tags.push('ransomware');
  if (/phishing/i.test(text))            tags.push('phishing');
  if (/apt|nation.?state/i.test(text))   tags.push('apt');
  if (/zero.?day/i.test(text))           tags.push('zero-day');
  if (/supply.?chain/i.test(text))       tags.push('supply-chain');
  if (/data.?breach/i.test(text))        tags.push('data-breach');
  if (/malware/i.test(text))             tags.push('malware');
  if (/vulnerability|cve/i.test(text))   tags.push('vulnerability');

  return { cves, actors, malware, severity, tags };
}

// ── Fetch and parse a single RSS feed ─────────────────────
async function fetchFeed(feed) {
  try {
    const { data } = await axios.get(feed.url, {
      timeout: 15000,
      headers: {
        'User-Agent':  'wadjet-eye-ai/5.2 (threat-intel-aggregator)',
        'Accept':      'application/rss+xml, application/xml, text/xml',
      },
      maxContentLength: 5 * 1024 * 1024,
    });

    const items = parseRSS(String(data));
    return items.map(item => ({
      ...item,
      source_name: feed.name,
      category:    feed.category,
    }));
  } catch (err) {
    console.warn(`[News][${feed.name}] Fetch error:`, err.message);
    return [];
  }
}

// ── Store articles in DB ──────────────────────────────────
async function storeArticles(articles, tenantId) {
  if (!articles || articles.length === 0) return { new: 0, updated: 0 };

  const tid = tenantId || DEFAULT_TENANT;
  const records = articles.map(a => ({
    tenant_id:     tid,
    title:         (a.title || '').slice(0, 500),
    url:           (a.link || '').slice(0, 1000),
    source:        a.source_name || 'unknown',
    category:      a.category || 'security-news',
    summary:       (a.description || '').replace(/<[^>]+>/g, '').slice(0, 2000),
    severity:      a.severity || 'medium',
    cves:          a.cves || [],
    threat_actors: a.actors || [],
    malware_families: a.malware || [],
    tags:          a.tags || [],
    published_at:  a.pubDate ? new Date(a.pubDate).toISOString() : new Date().toISOString(),
    external_guid: (a.guid || a.link || '').slice(0, 500),
  }));

  let newCount = 0, updatedCount = 0;

  // Upsert in chunks of 50
  for (let i = 0; i < records.length; i += 50) {
    const chunk = records.slice(i, i + 50);
    const { data, error } = await supabase
      .from('news_articles')
      .upsert(chunk, {
        onConflict:       'tenant_id,external_guid',
        ignoreDuplicates: false,
      })
      .select('id, created_at');

    if (error) {
      console.warn('[News] DB upsert error:', error.message);
      // Fall back to ignoreDuplicates
      await supabase.from('news_articles').upsert(chunk, {
        onConflict: 'tenant_id,external_guid',
        ignoreDuplicates: true,
      });
      updatedCount += chunk.length;
    } else if (data) {
      const cutoff = Date.now() - 15000;
      for (const row of data) {
        if (new Date(row.created_at).getTime() > cutoff) newCount++;
        else updatedCount++;
      }
    }
  }

  return { new: newCount, updated: updatedCount };
}

// ══════════════════════════════════════════════
//  Main News Ingestion Worker
// ══════════════════════════════════════════════
async function ingestCyberNews(tenantId) {
  const t0 = Date.now();
  console.info('[News] Starting cyber news ingestion...');

  let allArticles = [];
  let totalFetched = 0;

  for (const feed of RSS_FEEDS) {
    const items = await fetchFeed(feed);
    console.info(`[News][${feed.name}] Got ${items.length} articles`);

    for (const item of items) {
      const fullText  = `${item.title} ${item.description || ''}`;
      const entities  = extractEntities(fullText);
      allArticles.push({
        ...item,
        ...entities,
      });
    }
    totalFetched += items.length;

    // Be polite
    await new Promise(r => setTimeout(r, 500));
  }

  // Deduplicate by URL
  const seen   = new Set();
  const unique = [];
  for (const a of allArticles) {
    const key = a.link || a.guid;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(a);
    }
  }

  console.info(`[News] ${unique.length} unique articles to store`);

  // Store in DB
  const { new: n, updated: u } = await storeArticles(unique, tenantId);

  // For articles with CVEs, create/update alerts
  const criticalArticles = unique.filter(a =>
    a.severity === 'critical' && (a.cves.length > 0 || a.actors.length > 0)
  );

  for (const article of criticalArticles.slice(0, 5)) {
    await createNewsAlert(article, tenantId);
  }

  const result = {
    duration_ms:    Date.now() - t0,
    feeds_processed: RSS_FEEDS.length,
    total_fetched:  totalFetched,
    unique_articles: unique.length,
    articles_new:   n,
    articles_updated: u,
    critical_alerts: criticalArticles.length,
  };

  console.info(`[News] ✓ Done — new=${n} updated=${u} in ${result.duration_ms}ms`);
  return result;
}

// ── Create an alert for critical news ─────────────────────
async function createNewsAlert(article, tenantId) {
  try {
    await supabase.from('alerts').insert({
      tenant_id: tenantId || DEFAULT_TENANT,
      title:     article.title.slice(0, 200),
      severity:  article.severity,
      type:      'threat-intel',
      source:    article.source_name,
      status:    'open',
      description: article.summary?.slice(0, 1000) || '',
      metadata: {
        url:          article.link,
        cves:         article.cves,
        threat_actors: article.actors,
        malware:      article.malware,
        source:       'news_ingestion',
      },
    });
  } catch (_) {}
}

// ── Get recent news articles for API ──────────────────────
async function getRecentNews(tenantId, opts = {}) {
  const { limit = 20, severity, search } = opts;
  const tid = tenantId || DEFAULT_TENANT;

  let q = supabase
    .from('news_articles')
    .select('*')
    .or(`tenant_id.eq.${tid},tenant_id.is.null`)
    .order('published_at', { ascending: false })
    .limit(limit);

  if (severity) q = q.eq('severity', severity);
  if (search)   q = q.ilike('title', `%${search}%`);

  const { data, error } = await q;
  if (error) throw error;
  return data || [];
}

module.exports = {
  ingestCyberNews,
  getRecentNews,
  extractEntities,
  RSS_FEEDS,
};
