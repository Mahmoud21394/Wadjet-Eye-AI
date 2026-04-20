/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Cyber News RSS Ingestion Service v6.0
 *  backend/services/news-ingestion.js
 *
 *  Ingests cyber threat news from multiple RSS sources.
 *  - Category classification: threat-intel, vulnerabilities, cyber-attacks
 *  - Entity extraction: CVEs, threat actors, malware families
 *  - In-memory article cache for Supabase-less operation
 *  - Retry + timeout on every RSS fetch
 *  - Full logging of fetch failures and parse errors
 * ══════════════════════════════════════════════════════════
 */
'use strict';

const axios = require('axios');
let supabaseClient = null;
try { supabaseClient = require('../config/supabase').supabase; } catch (_) {}

const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';

// ── In-memory article cache (fallback when DB not available) ──────
let memCache  = [];
let lastIngest = 0;
const MEM_CACHE_TTL = 30 * 60 * 1000; // 30 min

// ── Known threat actor aliases ────────────────────────────────────
const KNOWN_ACTORS = [
  'APT1','APT2','APT3','APT4','APT10','APT17','APT18','APT19',
  'APT28','APT29','APT30','APT31','APT32','APT33','APT34','APT35',
  'APT37','APT38','APT40','APT41',
  'Lazarus Group','Lazarus','ZINC',
  'Cozy Bear','Fancy Bear','Sandworm','Turla','Gamaredon',
  'FIN7','FIN8','FIN6','FIN4',
  'Charming Kitten','Phosphorus','TA453',
  'Lapsus$','Scattered Spider','UNC3944',
  'REvil','Conti','LockBit','BlackCat','ALPHV','Hive','Cl0p',
  'MuddyWater','Kimsuky','SideWinder','Equation Group',
  'Volt Typhoon','Salt Typhoon','Flax Typhoon','Silk Typhoon',
  'Darkside','Ragnar Locker','BlackMatter','Vice Society',
];

// ── Known malware families ────────────────────────────────────────
const KNOWN_MALWARE = [
  'Cobalt Strike','Mimikatz','Metasploit','AsyncRAT','QuasarRAT',
  'njRAT','DarkComet','Agent Tesla','RedLine','Vidar','Raccoon',
  'IcedID','BazarLoader','TrickBot','Emotet','Qakbot','Dridex',
  'Ryuk','REvil','LockBit','BlackCat','Conti','Hive','Cl0p',
  'WannaCry','NotPetya','Petya','BlackEnergy','Industroyer',
  'PlugX','ShadowPad','Gh0stRAT','FinFisher','Pegasus',
  'Stuxnet','Flame','Duqu','RedEcho','Sunburst','Solorigate',
  'BlackMamba','NjRAT','BumbleBee','Brute Ratel','Sliver',
  'GootLoader','Ursnif','Rhadamanthys','StealC','Lumma',
];

// ── RSS feed definitions with primary category hint ──────────────
const RSS_FEEDS = [
  {
    name:     'The Hacker News',
    url:      'https://feeds.feedburner.com/TheHackersNews',
    category: 'threat-intelligence',
  },
  {
    name:     'BleepingComputer',
    url:      'https://www.bleepingcomputer.com/feed/',
    category: 'cyber-attacks',
  },
  {
    name:     'SecurityWeek',
    url:      'https://feeds.feedburner.com/securityweek',
    category: 'threat-intelligence',
  },
  {
    name:     'Krebs on Security',
    url:      'https://krebsonsecurity.com/feed/',
    category: 'cyber-attacks',
  },
  {
    name:     'CISA Alerts',
    url:      'https://www.cisa.gov/cybersecurity-advisories/all.xml',
    category: 'vulnerabilities',
  },
  {
    name:     'Dark Reading',
    url:      'https://www.darkreading.com/rss.xml',
    category: 'threat-intelligence',
  },
  {
    name:     'Threat Post',
    url:      'https://threatpost.com/feed/',
    category: 'threat-intelligence',
  },
  {
    name:     'SANS Internet Storm Center',
    url:      'https://isc.sans.edu/rssfeed_full.xml',
    category: 'vulnerabilities',
  },
];

// ── Category classifier by keywords ──────────────────────────────
function classifyCategory(text, feedDefault) {
  const t = text.toLowerCase();
  // Vulnerability signals
  if (/\bcve-\d{4}-\d{4,}/i.test(text) ||
      /\bzero.?day|patch tuesday|advisory|vulnerability|exploit kit|poc|proof.of.concept|security update/i.test(t))
    return 'vulnerabilities';
  // Cyber-attacks signals
  if (/\bransomware|breach|hack|attack|incident|campaign|ddos|data.?leak|stolen|exfiltrat|intrusion|espionage/i.test(t))
    return 'cyber-attacks';
  // Threat-intel signals
  if (/\bapt|nation.?state|threat.?actor|malware|c2|command.?control|ttps|mitre|ioc|indicator/i.test(t))
    return 'threat-intelligence';
  return feedDefault || 'threat-intelligence';
}

// ── Severity classifier ───────────────────────────────────────────
function classifySeverity(text) {
  if (/critical|zero.?day|actively exploit|in the wild|ransomware|nation.?state|supply.?chain attack/i.test(text))
    return 'critical';
  if (/high.sever|data breach|backdoor|rce|remote.?code|privilege.?escalat/i.test(text))
    return 'high';
  if (/patch|update|advisory|vulnerability|cve|medium/i.test(text))
    return 'medium';
  return 'low';
}

// ── Entity extractor ─────────────────────────────────────────────
function extractEntities(text) {
  const cves  = [...new Set((text.match(/CVE-\d{4}-\d{4,7}/gi) || []).map(c => c.toUpperCase()))].slice(0, 10);
  const actors   = KNOWN_ACTORS.filter(a => text.toLowerCase().includes(a.toLowerCase())).slice(0, 5);
  const malware  = KNOWN_MALWARE.filter(m => text.toLowerCase().includes(m.toLowerCase())).slice(0, 5);
  const severity = classifySeverity(text);

  const tags = [];
  if (/ransomware/i.test(text))         tags.push('ransomware');
  if (/phishing/i.test(text))           tags.push('phishing');
  if (/apt|nation.?state/i.test(text))  tags.push('apt');
  if (/zero.?day/i.test(text))          tags.push('zero-day');
  if (/supply.?chain/i.test(text))      tags.push('supply-chain');
  if (/data.?breach/i.test(text))       tags.push('data-breach');
  if (/malware/i.test(text))            tags.push('malware');
  if (/vulnerability|cve/i.test(text))  tags.push('vulnerability');
  if (/backdoor/i.test(text))           tags.push('backdoor');
  if (/espionage/i.test(text))          tags.push('espionage');

  return { cves, actors, malware, severity, tags };
}

// ── Simple RSS parser (no external deps) ────────────────────────
function parseRSS(xmlText) {
  const items  = [];
  const itemRx = /<item>([\s\S]*?)<\/item>/g;
  let m;

  while ((m = itemRx.exec(xmlText)) !== null) {
    const block = m[1];
    const getTag = (tag) => {
      const rx = new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tag}>|<${tag}[^>]*>([^<]*)<\\/${tag}>`);
      const tm = block.match(rx);
      if (!tm) return '';
      return (tm[1] || tm[2] || '').trim();
    };

    const title       = getTag('title');
    const link        = getTag('link') || (block.match(/<link>([^<]+)<\/link>/) || [])[1] || '';
    const description = getTag('description') || getTag('content:encoded') || '';
    const pubDate     = getTag('pubDate') || getTag('dc:date') || '';
    const guid        = getTag('guid') || link;

    if (title && link) {
      // ── Multi-source image extraction (priority order) ──────────────
      let imageUrl = null;

      // 1) <media:content url="..." medium="image"> — used by THN, SecurityWeek
      const mediaContent = block.match(/<media:content[^>]+url=["']([^"']+)["'][^>]*medium=["']image["']/i)
                        || block.match(/<media:content[^>]+medium=["']image["'][^>]+url=["']([^"']+)["']/i)
                        || block.match(/<media:content[^>]+url=["'](https?:\/\/[^"']+\.(jpg|jpeg|png|webp|gif)[^"']*)["']/i);
      if (mediaContent) imageUrl = mediaContent[1];

      // 2) <media:thumbnail url="..."> — BleepingComputer, others
      if (!imageUrl) {
        const mediaThumbnail = block.match(/<media:thumbnail[^>]+url=["']([^"']+)["']/i);
        if (mediaThumbnail) imageUrl = mediaThumbnail[1];
      }

      // 3) <enclosure url="..." type="image/..."> — podcast-style feeds
      if (!imageUrl) {
        const enclosure = block.match(/<enclosure[^>]+url=["']([^"']+)["'][^>]*type=["']image\//i)
                       || block.match(/<enclosure[^>]+type=["']image\/[^"']*["'][^>]+url=["']([^"']+)["']/i);
        if (enclosure) imageUrl = enclosure[1];
      }

      // 4) <img src="..."> inside description/content
      if (!imageUrl) {
        const imgMatch = description.match(/<img[^>]+src=["']([^"']+)["']/i);
        if (imgMatch) imageUrl = imgMatch[1];
      }

      // 5) og:image meta tag inside content
      if (!imageUrl) {
        const ogImg = block.match(/og:image[^>]*content=["']([^"']+)["']/i)
                   || block.match(/content=["'](https?:\/\/[^"']+\.(jpg|jpeg|png|webp)[^"']*)["']/i);
        if (ogImg) imageUrl = ogImg[1];
      }

      // 6) Any direct image URL in block
      if (!imageUrl) {
        const anyImg = block.match(/https?:\/\/[^\s"'<>]+\.(jpg|jpeg|png|webp)(\?[^\s"'<>]*)?/i);
        if (anyImg) imageUrl = anyImg[0];
      }

      // Validate image URL — must be absolute and point to an image
      if (imageUrl && !/^https?:\/\//i.test(imageUrl)) imageUrl = null;
      // Reject tracking pixels and tiny images
      if (imageUrl && /1x1|pixel|track|beacon/i.test(imageUrl)) imageUrl = null;

      // Clean HTML entities from description
      const cleanDesc = description
        .replace(/<[^>]+>/g, ' ')          // strip HTML tags
        .replace(/&nbsp;/g, ' ')           // non-breaking space
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&[a-z]+;/gi, '')         // remaining HTML entities
        .replace(/\s{2,}/g, ' ')           // collapse whitespace
        .trim()
        .slice(0, 600);

      items.push({ title, link: link.trim(), description: cleanDesc, imageUrl, pubDate, guid });
    }
  }
  return items;
}

// ── Fetch single RSS feed with retry ─────────────────────────────
async function fetchFeed(feed, retries = 2) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const { data } = await axios.get(feed.url, {
        timeout: 15000,
        headers: {
          'User-Agent': 'wadjet-eye-ai/6.0 threat-intel-aggregator',
          'Accept':     'application/rss+xml, application/xml, text/xml, */*',
        },
        maxContentLength: 8 * 1024 * 1024,
      });
      const items = parseRSS(String(data));
      return items.map(item => ({ ...item, source_name: feed.name, feedCategory: feed.category }));
    } catch (err) {
      if (attempt < retries) {
        console.warn(`[News][${feed.name}] Fetch attempt ${attempt + 1} failed: ${err.message} — retrying`);
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
      } else {
        console.error(`[News][${feed.name}] All ${retries + 1} fetch attempts failed: ${err.message}`);
      }
    }
  }
  return [];
}

// ── Store articles in Supabase ───────────────────────────────────
async function storeArticles(articles, tenantId) {
  if (!supabaseClient || !articles.length) return { new: 0, updated: 0 };

  const tid = tenantId || DEFAULT_TENANT;
  const records = articles.map(a => ({
    tenant_id:        tid,
    title:            (a.title || '').slice(0, 500),
    url:              (a.link  || '').slice(0, 1000),
    source:           a.source_name || 'unknown',
    category:         a.category || 'threat-intelligence',
    summary:          (a.description || '').slice(0, 2000),
    image_url:        a.imageUrl || null,
    severity:         a.severity || 'medium',
    cves:             a.cves || [],
    threat_actors:    a.actors || [],
    malware_families: a.malware || [],
    tags:             a.tags || [],
    published_at:     a.pubDate ? new Date(a.pubDate).toISOString() : new Date().toISOString(),
    external_guid:    (a.guid || a.link || '').slice(0, 500),
  }));

  let newCount = 0, updatedCount = 0;
  for (let i = 0; i < records.length; i += 50) {
    const chunk = records.slice(i, i + 50);
    try {
      const { data, error } = await supabaseClient
        .from('news_articles')
        .upsert(chunk, { onConflict: 'tenant_id,external_guid', ignoreDuplicates: false })
        .select('id, created_at');

      if (error) {
        console.warn('[News] DB upsert error:', error.message);
        updatedCount += chunk.length;
      } else if (data) {
        const cutoff = Date.now() - 15000;
        for (const row of data) {
          if (new Date(row.created_at).getTime() > cutoff) newCount++;
          else updatedCount++;
        }
      }
    } catch (dbErr) {
      console.error('[News] DB chunk error:', dbErr.message);
    }
  }
  return { new: newCount, updated: updatedCount };
}

// ════════════════════════════════════════════════════════════════
//  Main ingestion worker
// ════════════════════════════════════════════════════════════════
async function ingestCyberNews(tenantId) {
  const t0 = Date.now();
  console.info('[News] Starting cyber news ingestion v6.0...');

  let allArticles  = [];
  let totalFetched = 0;

  for (const feed of RSS_FEEDS) {
    const items = await fetchFeed(feed);
    console.info(`[News][${feed.name}] ${items.length} articles`);

    for (const item of items) {
      const fullText = `${item.title} ${item.description || ''}`;
      const entities = extractEntities(fullText);
      const category = classifyCategory(fullText, item.feedCategory);
      allArticles.push({ ...item, ...entities, category });
    }
    totalFetched += items.length;
    await new Promise(r => setTimeout(r, 300));
  }

  // Deduplicate by URL
  const seen   = new Set();
  const unique = [];
  for (const a of allArticles) {
    const key = a.link || a.guid;
    if (key && !seen.has(key)) { seen.add(key); unique.push(a); }
  }

  console.info(`[News] ${unique.length} unique articles (deduped from ${totalFetched})`);

  // Populate in-memory cache regardless of DB
  memCache   = unique.slice(0, 500);
  lastIngest = Date.now();

  // Attempt DB store
  const { new: n, updated: u } = await storeArticles(unique, tenantId);

  // Critical article alerts
  const criticals = unique.filter(a => a.severity === 'critical' && (a.cves.length > 0 || a.actors.length > 0));
  for (const article of criticals.slice(0, 5)) { await createNewsAlert(article, tenantId); }

  const result = {
    duration_ms:     Date.now() - t0,
    feeds_processed: RSS_FEEDS.length,
    total_fetched:   totalFetched,
    unique_articles: unique.length,
    articles_new:    n,
    articles_updated: u,
    critical_alerts: criticals.length,
  };
  console.info(`[News] ✓ Done — new=${n} updated=${u} in ${result.duration_ms}ms`);
  return result;
}

// ── Create alert for critical news ───────────────────────────────
async function createNewsAlert(article, tenantId) {
  if (!supabaseClient) return;
  try {
    await supabaseClient.from('alerts').insert({
      tenant_id:   tenantId || DEFAULT_TENANT,
      title:       article.title.slice(0, 200),
      severity:    article.severity,
      type:        'threat-intel',
      source:      article.source_name,
      status:      'open',
      description: (article.description || '').slice(0, 1000),
      metadata:    { url: article.link, cves: article.cves, threat_actors: article.actors, malware: article.malware, source: 'news_ingestion' },
    });
  } catch (_) {}
}

// ── Public API helper ─────────────────────────────────────────────
async function getRecentNews(tenantId, opts = {}) {
  const { limit = 50, severity, search, category, page = 1 } = opts;
  const tid      = tenantId || DEFAULT_TENANT;
  const pageNum  = Math.max(1, parseInt(page) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(limit) || 50));

  // Try DB first
  if (supabaseClient) {
    try {
      let q = supabaseClient
        .from('news_articles')
        .select('*', { count: 'exact' })
        .or(`tenant_id.eq.${tid},tenant_id.is.null`)
        .order('published_at', { ascending: false })
        .range((pageNum - 1) * pageSize, pageNum * pageSize - 1);

      if (severity) q = q.eq('severity', severity);
      if (category) q = q.eq('category', category);
      if (search)   q = q.ilike('title', `%${search}%`);

      const { data, error, count } = await q;
      if (!error && data && data.length > 0) {
        return { articles: data, total: count || data.length, source: 'db' };
      }
    } catch (dbErr) {
      console.warn('[News] DB query error, falling back to memory cache:', dbErr.message);
    }
  }

  // Fallback: trigger ingestion if cache is stale, then serve from memory
  if (memCache.length === 0 || Date.now() - lastIngest > MEM_CACHE_TTL) {
    console.info('[News] Memory cache stale — triggering background ingestion');
    ingestCyberNews(tid).catch(e => console.error('[News] Background ingest error:', e.message));
  }

  let articles = memCache;
  if (severity) articles = articles.filter(a => a.severity === severity);
  if (category) articles = articles.filter(a => a.category === category);
  if (search)   articles = articles.filter(a => a.title?.toLowerCase().includes(search.toLowerCase()));

  const start   = (pageNum - 1) * pageSize;
  const paged   = articles.slice(start, start + pageSize);
  return { articles: paged, total: articles.length, source: 'memory' };
}

module.exports = {
  ingestCyberNews,
  getRecentNews,
  extractEntities,
  classifyCategory,
  RSS_FEEDS,
};
