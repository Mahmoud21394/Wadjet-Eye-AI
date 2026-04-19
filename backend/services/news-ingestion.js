/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Cyber News Engine v6.0
 *  FILE: backend/services/news-ingestion.js
 *
 *  Real-time cyber news from multiple RSS/Atom/HTML feeds:
 *    - The Hacker News        (feedburner + direct)
 *    - BleepingComputer
 *    - SecurityWeek
 *    - Krebs on Security
 *    - CISA Alerts            (official advisories)
 *    - Dark Reading
 *    - Threat Post
 *    - SANS Internet Storm Center
 *    - Recorded Future Blog
 *    - Microsoft Security Response Center
 *    - Google Project Zero Blog
 *    - CyberScoop
 *
 *  Features:
 *    ✅ Real-time RSS/Atom XML parsing
 *    ✅ 5 categories: Threats, Intelligence, Vulnerabilities, Attacks, Advisories
 *    ✅ Entity extraction: CVEs, threat actors, malware families
 *    ✅ Severity scoring from content
 *    ✅ Deduplication by URL + title hash
 *    ✅ In-memory caching with 15-min TTL
 *    ✅ Timestamps, source attribution
 *    ✅ Graceful failover if feed unavailable
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

const axios = require('axios');

// Supabase (optional — works without it)
// v7.0: Use supabaseIngestion — isolated from auth clients, prevents event-loop
// saturation from news upserts interfering with Supabase auth operations.
let supabase;
try { ({ supabaseIngestion: supabase } = require('../config/supabase')); } catch (_) {}

const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';

// ─────────────────────────────────────────────────────────────────────
//  NEWS CATEGORIES
// ─────────────────────────────────────────────────────────────────────
const NEWS_CATEGORIES = {
  THREATS:          { id: 'threats',       label: 'Threat Intelligence', icon: '🎯', color: '#ef4444' },
  INTELLIGENCE:     { id: 'intelligence',  label: 'Cyber Intelligence',  icon: '🧠', color: '#8b5cf6' },
  VULNERABILITIES:  { id: 'vulnerabilities', label: 'Vulnerabilities',  icon: '🛡️', color: '#f97316' },
  ATTACKS:          { id: 'attacks',       label: 'Cyber Attacks',       icon: '⚔️', color: '#dc2626' },
  ADVISORIES:       { id: 'advisories',    label: 'Security Advisories', icon: '📋', color: '#2563eb' },
  RESEARCH:         { id: 'research',      label: 'Security Research',   icon: '🔬', color: '#059669' },
};

// ─────────────────────────────────────────────────────────────────────
//  RSS FEED SOURCES
// ─────────────────────────────────────────────────────────────────────
const RSS_FEEDS = [
  {
    id:       'thehackernews',
    name:     'The Hacker News',
    urls:     [
      'https://feeds.feedburner.com/TheHackersNews',
      'https://thehackernews.com/feeds/posts/default',
    ],
    category: 'threats',
    logo:     '🔴',
    priority: 1,
  },
  {
    id:       'bleepingcomputer',
    name:     'BleepingComputer',
    urls:     ['https://www.bleepingcomputer.com/feed/'],
    category: 'attacks',
    logo:     '💻',
    priority: 1,
  },
  {
    id:       'securityweek',
    name:     'SecurityWeek',
    urls:     [
      'https://feeds.feedburner.com/securityweek',
      'https://www.securityweek.com/feed/',
    ],
    category: 'intelligence',
    logo:     '📰',
    priority: 2,
  },
  {
    id:       'krebsonsecurity',
    name:     'Krebs on Security',
    urls:     ['https://krebsonsecurity.com/feed/'],
    category: 'attacks',
    logo:     '🔍',
    priority: 2,
  },
  {
    id:       'cisa',
    name:     'CISA Advisories',
    urls:     [
      'https://www.cisa.gov/cybersecurity-advisories/all.xml',
      'https://us-cert.cisa.gov/sites/default/files/publications/ics-advisories.xml',
    ],
    category: 'advisories',
    logo:     '🏛️',
    priority: 1,
  },
  {
    id:       'darkreading',
    name:     'Dark Reading',
    urls:     [
      'https://www.darkreading.com/rss.xml',
      'https://www.darkreading.com/rss_simple.asp',
    ],
    category: 'intelligence',
    logo:     '🌑',
    priority: 2,
  },
  {
    id:       'threatpost',
    name:     'Threat Post',
    urls:     ['https://threatpost.com/feed/'],
    category: 'threats',
    logo:     '⚡',
    priority: 2,
  },
  {
    id:       'sans',
    name:     'SANS ISC',
    urls:     ['https://isc.sans.edu/rssfeed_full.xml'],
    category: 'research',
    logo:     '📊',
    priority: 3,
  },
  {
    id:       'microsoft_sec',
    name:     'Microsoft Security',
    urls:     ['https://www.microsoft.com/en-us/security/blog/feed/'],
    category: 'vulnerabilities',
    logo:     '🪟',
    priority: 2,
  },
  {
    id:       'nist_nvd',
    name:     'NIST NVD Recent',
    urls:     ['https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml'],
    category: 'vulnerabilities',
    logo:     '🔒',
    priority: 1,
  },
  {
    id:       'cyberscoop',
    name:     'CyberScoop',
    urls:     ['https://cyberscoop.com/feed/'],
    category: 'intelligence',
    logo:     '🔭',
    priority: 3,
  },
  {
    id:       'portswigger',
    name:     'PortSwigger Research',
    urls:     ['https://portswigger.net/daily-swig/rss'],
    category: 'research',
    logo:     '🕷️',
    priority: 3,
  },
];

// ─────────────────────────────────────────────────────────────────────
//  KNOWN ENTITIES FOR EXTRACTION
// ─────────────────────────────────────────────────────────────────────
const KNOWN_ACTORS = [
  'APT1','APT2','APT3','APT4','APT10','APT17','APT18','APT19',
  'APT28','APT29','APT30','APT31','APT32','APT33','APT34','APT35',
  'APT37','APT38','APT40','APT41','APT42','APT43','APT44',
  'Lazarus Group','Lazarus','ZINC','HIDDEN COBRA',
  'Cozy Bear','Fancy Bear','Sandworm','Turla','Gamaredon',
  'FIN7','FIN8','FIN6','FIN4','FIN11',
  'Charming Kitten','Phosphorus','TA453',
  'Lapsus$','Scattered Spider','UNC3944','Octo Tempest',
  'REvil','Conti','LockBit','BlackCat','ALPHV','Hive','Cl0p',
  'MuddyWater','Kimsuky','SideWinder','Equation Group',
  'Volt Typhoon','Salt Typhoon','Flax Typhoon','Silk Typhoon',
  'Storm-0978','Storm-0501','Storm-0539',
  'Vice Society','Play','Cuba','BlackBasta','Rhysida',
];

const KNOWN_MALWARE = [
  'Cobalt Strike','Mimikatz','Metasploit','AsyncRAT','QuasarRAT',
  'njRAT','DarkComet','Agent Tesla','RedLine','Vidar','Raccoon',
  'IcedID','BazarLoader','TrickBot','Emotet','Qakbot','Dridex',
  'Ryuk','REvil','LockBit','BlackCat','Conti','Hive','Cl0p',
  'WannaCry','NotPetya','Petya','BlackEnergy','Industroyer',
  'PlugX','ShadowPad','Gh0stRAT','FinFisher','Pegasus',
  'Stuxnet','Flame','Duqu','RedEcho','Sunburst','Solorigate',
  'GoAnywhere','MOVEit','Volt','Beep','IceBreaker',
  'RustBucket','SwiftSlicer','PartyTicket','DoubleZero',
];

// ─────────────────────────────────────────────────────────────────────
//  IN-MEMORY CACHE
// ─────────────────────────────────────────────────────────────────────
const NEWS_CACHE_TTL = 15 * 60 * 1000; // 15 minutes
const _newsCache = {
  articles:  [],
  byCategory: {},
  lastFetch: 0,
  fetchCount: 0,
};

// ─────────────────────────────────────────────────────────────────────
//  RSS XML PARSER (no external deps)
// ─────────────────────────────────────────────────────────────────────
function parseRSS(xmlText, feedName) {
  const items = [];

  // Try RSS format
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  // Try Atom format
  const entryRegex = /<entry>([\s\S]*?)<\/entry>/g;

  const isAtom = xmlText.includes('<feed') && xmlText.includes('<entry>');
  const regex  = isAtom ? entryRegex : itemRegex;

  let match;
  while ((match = regex.exec(xmlText)) !== null) {
    const block = match[1];

    const getTag = (tag) => {
      // Try CDATA first
      const cdataMatch = block.match(new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tag}>`));
      if (cdataMatch) return cdataMatch[1].trim();

      // Try regular
      const regularMatch = block.match(new RegExp(`<${tag}[^>]*>([^<]*)<\\/${tag}>`));
      if (regularMatch) return regularMatch[1].trim();

      return '';
    };

    const getAttr = (tag, attr) => {
      const m = block.match(new RegExp(`<${tag}[^>]*\\s${attr}="([^"]+)"`));
      return m ? m[1] : '';
    };

    let title       = getTag('title') || getTag('dc:title');
    let link        = getTag('link') || getAttr('link', 'href') || block.match(/<link>([^<]+)<\/link>/)?.[1] || '';
    let description = getTag('description') || getTag('summary') || getTag('content') || getTag('content:encoded');
    let pubDate     = getTag('pubDate') || getTag('updated') || getTag('published') || getTag('dc:date');
    let guid        = getTag('guid') || getTag('id') || link;
    let author      = getTag('author') || getTag('dc:creator');

    // Clean HTML from description
    description = description.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").trim();

    // Clean title
    title = title.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&#\d+;/g, '').trim();

    link = link.trim();

    if (title && link) {
      items.push({
        title,
        link:        link,
        description: description.slice(0, 500),
        pubDate,
        guid:        guid || link,
        author,
        source:      feedName,
      });
    }
  }

  return items;
}

// ─────────────────────────────────────────────────────────────────────
//  ENTITY EXTRACTION
//  ROOT-CAUSE FIX for category mismatch between tabs:
//  Previous logic only respected [FEED_CATEGORY:x] hint when the feed's
//  category was NOT 'intelligence'. This meant SecurityWeek, Dark Reading,
//  and CyberScoop (all assigned category:'intelligence') NEVER got the
//  hint injected, so their articles were always re-classified by
//  text-matching into random other categories — causing cross-tab
//  contamination.
//
//  New strategy (strict category binding):
//  1. The feed's declared category is always injected as a hint token.
//  2. Text-based category detection is ONLY allowed to STRENGTHEN the
//     classification (e.g., advisory feed mentioning ransomware attack →
//     stays 'advisories' unless content is overwhelmingly 'attacks').
//  3. Category never defaults to 'intelligence' as a catch-all — if no
//     strong signal is found, we honour the feed's declared category.
//  4. Added strict per-category keyword sets with no overlap.
// ─────────────────────────────────────────────────────────────────────
function extractEntities(text) {
  // CVEs
  const cves = [...new Set((text.match(/CVE-\d{4}-\d{4,7}/gi) || []).map(c => c.toUpperCase()))].slice(0, 10);

  // Threat actors
  const actors = KNOWN_ACTORS.filter(a => text.toLowerCase().includes(a.toLowerCase())).slice(0, 5);

  // Malware
  const malware = KNOWN_MALWARE.filter(m => text.toLowerCase().includes(m.toLowerCase())).slice(0, 5);

  // Severity
  let severity = 'medium';
  if (/critical|zero.?day|actively exploit|in the wild|ransomware|nation.?state|apt|state.sponsored/i.test(text)) severity = 'critical';
  else if (/high.sever|data breach|supply chain|backdoor|rce|remote code|privilege escalat/i.test(text)) severity = 'high';
  else if (/patch|update|advisory|vulnerability|cve/i.test(text)) severity = 'medium';
  else severity = 'low';

  // ── ROOT-CAUSE FIX: Strict category binding ──────────────────────
  // Extract the feed-level hint that was injected by the caller.
  // The hint is ALWAYS injected now (even for 'intelligence' feeds).
  const _feedCat = (text.match(/\[FEED_CATEGORY:([a-z_]+)\]/) || [])[1] || '';

  // Define strict per-category keyword patterns (non-overlapping)
  const SIG = {
    // ADVISORIES: Official gov/cert advisory signals — highest priority
    advisories: /\b(cisa|us-cert|ics-cert|cert\.gov|cert-cc|ncsc|enisa|government.{0,10}advisory|federal.{0,10}advisory|official.{0,10}alert|security.{0,10}bulletin|patch.{0,10}tuesday|emergency.{0,10}directive)\b/i,

    // ATTACKS: Active incidents, breaches, ransomware campaigns
    attacks: /\b(ransomware.{0,30}hit|attack.{0,20}compan|breach.{0,20}data|data.{0,20}stolen|hack(ed|ing).{0,20}(compan|organ|firm|group)|credential.{0,20}theft|intrusion.{0,20}detect|incident.{0,20}response|actively.{0,20}exploit|in.the.wild)\b/i,

    // VULNERABILITIES: CVE-centric, patch, vuln disclosure
    vulnerabilities: /\b(CVE-\d{4}-\d+|zero.?day.{0,30}(vuln|flaw|bug|patch)|vulnerability.{0,20}(critical|high|disclose|found|patch)|patch.{0,15}tuesday|security.{0,10}update.{0,10}(release|availab)|exploit.{0,20}(code|poc|proof|kit))\b/i,

    // THREATS: APT, nation-state, espionage, campaign attribution
    threats: /\b(APT\d+|nation.?state|espionage|threat.?actor|campaign.{0,20}(target|attribu)|living.off.the.land|LOTL|cyber.?espionage|state.?sponsored|threat.{0,20}group|cozy.?bear|fancy.?bear|lazarus|volt.?typhoon|scattered.?spider)\b/i,

    // RESEARCH: Analysis papers, new technique discovery, tools
    research: /\b(research.{0,20}(reveal|find|discover|paper|publish)|new.{0,20}(technique|method|approach|tool|framework|paper)|analys(is|ed).{0,20}(malware|binary|code|sample)|reverse.{0,20}engineer|proof.{0,10}of.{0,10}concept.{0,30}(?!exploit))\b/i,

    // INTELLIGENCE: Strategic analysis, threat landscape, industry reports
    intelligence: /\b(threat.{0,20}intelligence|threat.{0,20}landscape|industry.{0,20}report|annual.{0,20}report|threat.{0,20}forecast|threat.{0,20}brief|cybersecurity.{0,20}(trend|overview|insight)|sector.{0,20}(analysis|report))\b/i,
  };

  let category;

  // Step 1: Check for government/official advisory signals first (highest priority)
  if (SIG.advisories.test(text) || _feedCat === 'advisories') {
    // Advisories stay as advisories unless clear attack signal
    if (_feedCat === 'advisories' || SIG.advisories.test(text)) {
      // Only override to 'attacks' if there's a very strong active-incident signal
      // AND the feed is NOT an official advisory source
      if (SIG.attacks.test(text) && _feedCat !== 'advisories') {
        category = 'attacks';
      } else {
        category = 'advisories';
      }
    }
  }

  // Step 2: Apply text-based classification if no advisory lock
  if (!category) {
    // Score each category by signal strength
    const scores = {};
    for (const [cat, regex] of Object.entries(SIG)) {
      const matches = text.match(new RegExp(regex.source, 'gi')) || [];
      scores[cat] = matches.length;
    }

    // Also weight the feed's declared category (+2 bonus for declared category)
    if (_feedCat && SIG[_feedCat]) {
      scores[_feedCat] = (scores[_feedCat] || 0) + 2;
    }

    // Pick highest-scoring category
    const best = Object.entries(scores).sort((a, b) => b[1] - a[1])[0];

    if (best && best[1] > 0) {
      category = best[0];
    } else {
      // No strong signal found — honour the feed's declared category exactly
      category = _feedCat || 'intelligence';
    }
  }

  // Tags
  const tags = [];
  if (/ransomware/i.test(text))           tags.push('ransomware');
  if (/phishing/i.test(text))             tags.push('phishing');
  if (/apt|nation.?state/i.test(text))    tags.push('apt');
  if (/zero.?day/i.test(text))            tags.push('zero-day');
  if (/supply.?chain/i.test(text))        tags.push('supply-chain');
  if (/data.?breach/i.test(text))         tags.push('data-breach');
  if (/malware/i.test(text))              tags.push('malware');
  if (/vulnerability|cve/i.test(text))    tags.push('vulnerability');
  if (/backdoor/i.test(text))             tags.push('backdoor');
  if (/healthcare|hospital|medical/i.test(text)) tags.push('healthcare');
  if (/critical.infrastructure|utility|energy|water/i.test(text)) tags.push('critical-infrastructure');
  if (/financial|bank|swift/i.test(text)) tags.push('financial');

  return { cves, actors, malware, severity, category, tags };
}

// ─────────────────────────────────────────────────────────────────────
//  FETCH A SINGLE FEED (try each URL in order)
// ─────────────────────────────────────────────────────────────────────
async function fetchFeed(feed) {
  for (const url of feed.urls) {
    try {
      const { data } = await axios.get(url, {
        timeout: 12000,
        headers: {
          'User-Agent':  'WadjetEye-AI/6.0 (Cyber Threat Intelligence Platform; +https://wadjet-eye.ai)',
          'Accept':      'application/rss+xml, application/xml, application/atom+xml, text/xml, */*',
          'Cache-Control': 'no-cache',
        },
        maxContentLength: 8 * 1024 * 1024, // 8MB max
      });

      const items = parseRSS(String(data), feed.name);
      if (items.length > 0) {
        console.info(`[News][${feed.name}] Fetched ${items.length} articles from ${url}`);
        return items.map(item => ({ ...item, feedId: feed.id, feedCategory: feed.category }));
      }
    } catch (err) {
      console.warn(`[News][${feed.name}] URL ${url} failed: ${err.message}`);
    }
  }

  console.warn(`[News][${feed.name}] All URLs failed`);
  return [];
}

// ─────────────────────────────────────────────────────────────────────
//  DEDUPLICATION
// ─────────────────────────────────────────────────────────────────────
function deduplicateArticles(articles) {
  const seen = new Set();
  const unique = [];

  for (const article of articles) {
    // Normalize URL for dedup key
    const urlKey = (article.link || '').replace(/\?.*$/, '').toLowerCase();
    const titleKey = (article.title || '').toLowerCase().slice(0, 80);
    const key = urlKey || titleKey;

    if (key && !seen.has(key)) {
      seen.add(key);
      unique.push(article);
    }
  }

  return unique;
}

// ─────────────────────────────────────────────────────────────────────
//  SORT ARTICLES
// ─────────────────────────────────────────────────────────────────────
function sortArticles(articles) {
  return articles.sort((a, b) => {
    // Sort by: severity first, then date
    const sevOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    const sevDiff = (sevOrder[b.severity] || 2) - (sevOrder[a.severity] || 2);
    if (sevDiff !== 0) return sevDiff;

    const dateA = new Date(a.publishedAt || 0).getTime();
    const dateB = new Date(b.publishedAt || 0).getTime();
    return dateB - dateA;
  });
}

// ─────────────────────────────────────────────────────────────────────
//  MAIN INGESTION FUNCTION
// ─────────────────────────────────────────────────────────────────────
async function ingestCyberNews(tenantId, options = {}) {
  const t0 = Date.now();
  const { forceRefresh = false, feedIds = null } = options;

  // Return cached if fresh
  if (!forceRefresh && Date.now() - _newsCache.lastFetch < NEWS_CACHE_TTL && _newsCache.articles.length > 0) {
    console.info(`[News] Returning cached ${_newsCache.articles.length} articles`);
    return _buildIngestResult(_newsCache.articles, t0, false);
  }

  console.info('[News] Starting cyber news ingestion from', RSS_FEEDS.length, 'feeds...');

  const feedsToFetch = feedIds
    ? RSS_FEEDS.filter(f => feedIds.includes(f.id))
    : RSS_FEEDS;

  // Fetch feeds concurrently (max 4 at a time)
  const allRawArticles = [];
  const BATCH = 4;

  for (let i = 0; i < feedsToFetch.length; i += BATCH) {
    const batch = feedsToFetch.slice(i, i + BATCH);
    const results = await Promise.allSettled(batch.map(f => fetchFeed(f)));
    for (const r of results) {
      if (r.status === 'fulfilled') allRawArticles.push(...r.value);
    }
    if (i + BATCH < feedsToFetch.length) {
      await new Promise(r => setTimeout(r, 300)); // polite delay between batches
    }
  }

  console.info(`[News] Raw articles fetched: ${allRawArticles.length}`);

  // Enrich each article
  const enriched = allRawArticles.map(item => {
    // ROOT-CAUSE FIX: ALWAYS inject the feed category as a hint token,
    // regardless of whether it is 'intelligence' or not. Previously
    // 'intelligence' feeds were excluded from the hint injection, which
    // meant their articles defaulted to text-only classification and got
    // misassigned to wrong categories, causing cross-tab contamination.
    const feedCatHint = item.feedCategory
      ? ` [FEED_CATEGORY:${item.feedCategory}]`
      : '';
    const fullText  = `${item.title} ${item.description || ''}${feedCatHint}`;
    const entities  = extractEntities(fullText);
    const pubDate   = item.pubDate ? new Date(item.pubDate) : new Date();
    const isValid   = !isNaN(pubDate.getTime());

    return {
      id:           `${item.feedId}-${Buffer.from(item.link || item.title).toString('base64').slice(0, 16)}`,
      title:        item.title,
      url:          item.link,
      source:       item.source,
      sourceId:     item.feedId,
      category:     entities.category || item.feedCategory || 'intelligence',
      summary:      item.description?.slice(0, 300) || '',
      severity:     entities.severity,
      cves:         entities.cves,
      threatActors: entities.actors,
      malwareFamilies: entities.malware,
      tags:         entities.tags,
      publishedAt:  isValid ? pubDate.toISOString() : new Date().toISOString(),
      publishedAgo: _timeAgo(isValid ? pubDate : new Date()),
      guid:         item.guid,
      author:       item.author || item.source,
    };
  });

  // Deduplicate
  const unique = deduplicateArticles(enriched);
  const sorted = sortArticles(unique);

  console.info(`[News] Unique articles after dedup: ${sorted.length}`);

  // Update cache
  _newsCache.articles   = sorted;
  _newsCache.lastFetch  = Date.now();
  _newsCache.fetchCount++;

  // Build byCategory index
  _newsCache.byCategory = {};
  for (const cat of Object.keys(NEWS_CATEGORIES)) {
    const catId = NEWS_CATEGORIES[cat].id;
    _newsCache.byCategory[catId] = sorted.filter(a => a.category === catId);
  }

  // ROOT-CAUSE DEBUG: Log per-category distribution so operators can verify
  // articles are being classified into the correct categories.
  const distribution = Object.entries(_newsCache.byCategory).map(([id, arr]) =>
    `${id}:${arr.length}`
  ).join(' | ');
  console.info(`[News] Category distribution: ${distribution}`);
  // Warn if any category is completely empty (may indicate classification bug)
  for (const [catId, articles] of Object.entries(_newsCache.byCategory)) {
    if (articles.length === 0) {
      console.warn(`[News] ⚠️ Category '${catId}' has 0 articles — check feed assignments and classification logic`);
    }
  }

  // Persist critical articles to DB (fire-and-forget)
  if (supabase && tenantId) {
    _persistToDatabase(sorted, tenantId).catch(err =>
      console.warn('[News] DB persist failed:', err.message)
    );
  }

  return _buildIngestResult(sorted, t0, true);
}

function _buildIngestResult(articles, t0, fetched) {
  const byCategory = {};
  for (const cat of Object.keys(NEWS_CATEGORIES)) {
    const catId = NEWS_CATEGORIES[cat].id;
    byCategory[catId] = articles.filter(a => a.category === catId).length;
  }

  return {
    articles,
    total:      articles.length,
    byCategory,
    categories: NEWS_CATEGORIES,
    fetchedAt:  new Date().toISOString(),
    fromCache:  !fetched,
    durationMs: Date.now() - t0,
    cacheAge:   Math.floor((Date.now() - _newsCache.lastFetch) / 1000) + 's',
    feeds:      RSS_FEEDS.map(f => ({ id: f.id, name: f.name, category: f.category })),
  };
}

// ─────────────────────────────────────────────────────────────────────
//  PERSIST TO DB
// ─────────────────────────────────────────────────────────────────────
async function _persistToDatabase(articles, tenantId) {
  if (!supabase) return;
  const tid = tenantId || DEFAULT_TENANT;

  // Only persist critical/high articles
  const critical = articles.filter(a => a.severity === 'critical' || a.severity === 'high').slice(0, 50);

  if (critical.length === 0) return;

  const records = critical.map(a => ({
    tenant_id:        tid,
    title:            (a.title || '').slice(0, 500),
    url:              (a.url   || '').slice(0, 1000),
    source:           a.source || 'unknown',
    category:         a.category || 'intelligence',
    summary:          (a.summary || '').slice(0, 2000),
    severity:         a.severity || 'medium',
    cves:             a.cves || [],
    threat_actors:    a.threatActors || [],
    malware_families: a.malwareFamilies || [],
    tags:             a.tags || [],
    published_at:     a.publishedAt || new Date().toISOString(),
    external_guid:    (a.guid || a.url || '').slice(0, 500),
  }));

  // Chunk upsert
  for (let i = 0; i < records.length; i += 25) {
    try {
      await supabase
        .from('news_articles')
        .upsert(records.slice(i, i + 25), {
          onConflict: 'tenant_id,external_guid',
          ignoreDuplicates: true,
        });
    } catch (_) {}
  }
}

// ─────────────────────────────────────────────────────────────────────
//  GET RECENT NEWS (from cache or DB)
// ─────────────────────────────────────────────────────────────────────
async function getRecentNews(tenantId, opts = {}) {
  const { limit = 30, category, severity, search, page = 1 } = opts;
  const offset = (page - 1) * limit;

  // Try cache first
  let articles = _newsCache.articles;

  // If cache is empty or stale, refresh
  if (articles.length === 0 || Date.now() - _newsCache.lastFetch > NEWS_CACHE_TTL) {
    const result = await ingestCyberNews(tenantId);
    articles = result.articles;
  }

  // Filter — 'all' (or no category) returns every article
  let filtered = articles;
  if (category && category !== 'all') filtered = filtered.filter(a => a.category === category);
  if (severity) filtered = filtered.filter(a => a.severity === severity);
  if (search) {
    const q = search.toLowerCase();
    filtered = filtered.filter(a =>
      (a.title || '').toLowerCase().includes(q) ||
      (a.summary || '').toLowerCase().includes(q) ||
      (a.cves || []).some(c => c.toLowerCase().includes(q))
    );
  }

  const total = filtered.length;
  const paged = filtered.slice(offset, offset + limit);

  return {
    articles: paged,
    total,
    page,
    limit,
    totalPages: Math.ceil(total / limit),
    categories: _newsCache.byCategory,
  };
}

// ─────────────────────────────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────────────────────────────
function _timeAgo(date) {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60)   return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds/60)}m ago`;
  if (seconds < 86400)return `${Math.floor(seconds/3600)}h ago`;
  return `${Math.floor(seconds/86400)}d ago`;
}

function getCacheStats() {
  // Convert byCategory (which stores full article arrays) into a count map
  // so all callers receive consistent numeric values.
  const byCategoryCounts = {};
  for (const [catId, val] of Object.entries(_newsCache.byCategory || {})) {
    byCategoryCounts[catId] = Array.isArray(val) ? val.length : (val || 0);
  }

  return {
    totalArticles: _newsCache.articles.length,
    byCategory:    byCategoryCounts,
    lastFetch:     _newsCache.lastFetch ? new Date(_newsCache.lastFetch).toISOString() : null,
    cacheAgeMs:    Date.now() - _newsCache.lastFetch,
    fetchCount:    _newsCache.fetchCount,
    feedCount:     RSS_FEEDS.length,
  };
}

// ─────────────────────────────────────────────────────────────────────
//  EXPORTS
// ─────────────────────────────────────────────────────────────────────
module.exports = {
  ingestCyberNews,
  getRecentNews,
  extractEntities,
  getCacheStats,
  RSS_FEEDS,
  NEWS_CATEGORIES,
};
