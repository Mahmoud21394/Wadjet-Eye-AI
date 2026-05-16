/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Multilingual Dark Web Intelligence Processor  v1.0
 *  backend/services/darkweb/multilingual-processor.js
 *
 *  INNOVATION-003: Multi-language Dark Web Intelligence
 *  ─────────────────────────────────────────────────────
 *  Dark web forums, ransomware sites, and paste dumps frequently
 *  use Russian, Chinese, Arabic, Farsi, and other languages.
 *  Restricting intelligence to English-only misses ~60% of signals.
 *
 *  This module provides:
 *  1. Language detection using `franc` (lightweight, no API needed)
 *  2. Translation to English via DeepL API (high accuracy for security text)
 *  3. Named Entity Recognition (NER) — extracts org names, countries,
 *     malware families, and financial entities from translated text
 *  4. Confidence-weighted IOC extraction from multilingual content
 *
 *  Language support:
 *    Russian (rus), Chinese Simplified (cmn), Arabic (ara),
 *    Persian/Farsi (fas), Turkish (tur), Spanish (spa),
 *    Portuguese (por), French (fra), German (deu), Korean (kor)
 *    + English (eng) passthrough
 *
 *  Feature flags:
 *    FEATURE_MULTILINGUAL_DW=true   — enable this module
 *
 *  Required env vars:
 *    DEEPL_API_KEY                  — DeepL API free/pro key
 *    FEATURE_MULTILINGUAL_DW        — feature flag
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const https  = require('https');
const crypto = require('crypto');

// ── Feature flag ───────────────────────────────────────────────────
const FEATURE_ENABLED = process.env.FEATURE_MULTILINGUAL_DW === 'true';

// ── Language detection via franc ──────────────────────────────────

/**
 * detectLanguage — identify the ISO 639-3 language code of the input text.
 *
 * Uses `franc` if installed; falls back to a simple heuristic for
 * Cyrillic/CJK/Arabic script detection when franc is unavailable.
 *
 * @param {string} text
 * @returns {{ code: string, confidence: number, name: string }}
 */
function detectLanguage(text) {
  if (!text || text.length < 20) {
    return { code: 'und', confidence: 0, name: 'Undetermined' };
  }

  // Try franc first
  let franc;
  try { franc = require('franc'); } catch { franc = null; }

  if (franc) {
    const result = franc(text, { minLength: 20 });
    return {
      code:       result,
      confidence: result === 'und' ? 0 : 0.8, // franc doesn't expose confidence
      name:       LANGUAGE_NAMES[result] || result,
    };
  }

  // Fallback: script-based heuristic
  return scriptHeuristicDetect(text);
}

/**
 * scriptHeuristicDetect — simple Unicode block detection fallback.
 * @param {string} text
 * @returns {{ code: string, confidence: number, name: string }}
 */
function scriptHeuristicDetect(text) {
  const counts = { cyrillic: 0, cjk: 0, arabic: 0, latin: 0, other: 0 };
  const total  = text.length;

  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp >= 0x0400 && cp <= 0x04FF) counts.cyrillic++;
    else if ((cp >= 0x4E00 && cp <= 0x9FFF) || (cp >= 0x3000 && cp <= 0x303F)) counts.cjk++;
    else if ((cp >= 0x0600 && cp <= 0x06FF) || (cp >= 0x0750 && cp <= 0x077F)) counts.arabic++;
    else if ((cp >= 0x0041 && cp <= 0x007A) || (cp >= 0x00C0 && cp <= 0x024F)) counts.latin++;
    else counts.other++;
  }

  const dominant = Object.entries(counts).sort(([,a],[,b]) => b - a)[0];
  const ratio    = dominant[1] / total;

  if (ratio < 0.1) return { code: 'und', confidence: 0, name: 'Undetermined' };

  const scriptMap = {
    cyrillic: { code: 'rus', name: 'Russian' },
    cjk:      { code: 'cmn', name: 'Chinese' },
    arabic:   { code: 'ara', name: 'Arabic' },
    latin:    { code: 'eng', name: 'English' },
  };

  const lang = scriptMap[dominant[0]] || { code: 'und', name: 'Undetermined' };
  return { ...lang, confidence: parseFloat(ratio.toFixed(2)) };
}

const LANGUAGE_NAMES = {
  eng: 'English',   rus: 'Russian',    cmn: 'Chinese',
  ara: 'Arabic',    fas: 'Persian',    tur: 'Turkish',
  spa: 'Spanish',   por: 'Portuguese', fra: 'French',
  deu: 'German',    kor: 'Korean',     jpn: 'Japanese',
  ukr: 'Ukrainian', pol: 'Polish',     heb: 'Hebrew',
  hin: 'Hindi',     und: 'Undetermined',
};

// franc ISO 639-3 → DeepL source language code mapping
const FRANC_TO_DEEPL = {
  rus: 'RU', cmn: 'ZH', ara: 'AR', fas: null, // DeepL doesn't support Farsi
  tur: 'TR', spa: 'ES', por: 'PT', fra: 'FR',
  deu: 'DE', kor: 'KO', jpn: 'JA', ukr: 'UK',
  pol: 'PL',
};

// ── DeepL translation ──────────────────────────────────────────────

const DEEPL_API_KEY   = () => process.env.DEEPL_API_KEY;
const DEEPL_API_URL   = 'https://api-free.deepl.com'; // use api.deepl.com for Pro plan

/**
 * translateToEnglish — translate text to English using DeepL API.
 *
 * @param {string} text - Source text
 * @param {string} sourceLangCode - DeepL source language (e.g. 'RU', 'ZH')
 * @returns {Promise<{ translated: string, detected_language: string, service: string }>}
 */
async function translateToEnglish(text, sourceLangCode) {
  const apiKey = DEEPL_API_KEY();

  if (!apiKey) {
    console.warn('[Multilingual] DEEPL_API_KEY not set — skipping translation');
    return { translated: text, detected_language: sourceLangCode, service: 'passthrough', error: 'no_api_key' };
  }

  if (!sourceLangCode || sourceLangCode === 'EN') {
    return { translated: text, detected_language: 'EN', service: 'passthrough' };
  }

  // Truncate to DeepL's 10,000 char limit
  const truncated = text.slice(0, 10000);

  const params = new URLSearchParams({
    text:        truncated,
    target_lang: 'EN-US',
    source_lang: sourceLangCode,
    preserve_formatting: '1',
  });

  const payload = params.toString();

  return new Promise((resolve) => {
    const req = https.request({
      hostname: new URL(DEEPL_API_URL).hostname,
      port:     443,
      path:     '/v2/translate',
      method:   'POST',
      headers: {
        'Authorization':  `DeepL-Auth-Key ${apiKey}`,
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: 15000,
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const body      = JSON.parse(Buffer.concat(chunks).toString());
          const tr        = body.translations?.[0];
          resolve({
            translated:         tr?.text || text,
            detected_language:  tr?.detected_source_language || sourceLangCode,
            service:            'deepl',
            char_count:         truncated.length,
          });
        } catch (e) {
          resolve({ translated: text, detected_language: sourceLangCode, service: 'deepl_parse_error', error: e.message });
        }
      });
    });

    req.on('error', err => resolve({ translated: text, detected_language: sourceLangCode, service: 'deepl_error', error: err.message }));
    req.on('timeout', () => { req.destroy(); resolve({ translated: text, detected_language: sourceLangCode, service: 'deepl_timeout' }); });
    req.write(payload);
    req.end();
  });
}

// ── Named Entity Recognition (NER) ────────────────────────────────

/**
 * extractNamedEntities — lightweight regex-based NER for security text.
 *
 * Extracts:
 *  - Organisation names (capitalised n-grams near org keywords)
 *  - Country names
 *  - Malware family names
 *  - Monetary amounts (ransom demands)
 *  - Bitcoin/Monero addresses
 *
 * @param {string} englishText - Translated (or original) English text
 * @returns {object}
 */
function extractNamedEntities(englishText) {
  const entities = {
    organisations:   [],
    countries:       [],
    malware_families: [],
    ransom_amounts:  [],
    crypto_addresses: [],
  };

  // Organisation mentions near breach/hack/attack keywords
  const orgPattern = /\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\s+(?:was|has been|suffered|reported|confirmed|disclosed)\b/g;
  let m;
  while ((m = orgPattern.exec(englishText)) !== null) {
    if (m[1].length > 3) entities.organisations.push(m[1]);
  }

  // Country names
  const COUNTRIES = ['United States', 'Russia', 'China', 'Iran', 'North Korea', 'Ukraine', 'Germany', 'France', 'Israel', 'India', 'UK', 'USA', 'EU'];
  for (const c of COUNTRIES) {
    if (englishText.includes(c)) entities.countries.push(c);
  }

  // Malware family names (common ones in dark web context)
  const MALWARE_REGEX = /\b(LockBit|BlackCat|ALPHV|Cl0p|Akira|Play|Rhysida|RansomHub|Conti|Hive|BlackMatter|DarkSide|REvil|Ryuk|Emotet|TrickBot|QBot|IcedID|Cobalt Strike|Sliver|Havoc|Brute Ratel)\b/gi;
  while ((m = MALWARE_REGEX.exec(englishText)) !== null) {
    entities.malware_families.push(m[1]);
  }
  entities.malware_families = [...new Set(entities.malware_families)];

  // Ransom amounts
  const ransomPattern = /\$\s*([\d,]+(?:\.\d+)?)\s*(?:million|M|thousand|k|USD|BTC|XMR)?/gi;
  while ((m = ransomPattern.exec(englishText)) !== null) {
    entities.ransom_amounts.push(m[0].trim());
  }

  // Crypto addresses
  const BTC_REGEX  = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g;
  const XMR_REGEX  = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g;
  entities.crypto_addresses.push(...[...englishText.matchAll(BTC_REGEX)].map(m => ({ type: 'BTC', address: m[0] })));
  entities.crypto_addresses.push(...[...englishText.matchAll(XMR_REGEX)].map(m => ({ type: 'XMR', address: m[0] })));

  // Deduplicate organisations
  entities.organisations = [...new Set(entities.organisations)].slice(0, 20);

  return entities;
}

// ─────────────────────────────────────────────────────────────────
//  Main processing pipeline
// ─────────────────────────────────────────────────────────────────

/**
 * processFinding — process a single dark web finding through the
 * multilingual pipeline: detect → translate → NER → return enriched.
 *
 * @param {object} finding - A dark web finding from darkweb-monitor
 * @returns {Promise<object>} Enriched finding with translation metadata
 */
async function processFinding(finding) {
  if (!FEATURE_ENABLED) {
    return { ...finding, multilingual: { skipped: true } };
  }

  const text = finding.snippet || finding.data || '';
  if (!text || text.length < 20) {
    return { ...finding, multilingual: { skipped: true, reason: 'insufficient_text' } };
  }

  // Layer 1: Language detection
  const langResult   = detectLanguage(text);
  const deeplLang    = FRANC_TO_DEEPL[langResult.code];
  const isEnglish    = langResult.code === 'eng' || langResult.code === 'und';

  let translatedText = text;
  let translationMeta = { service: 'passthrough', source_language: langResult.code };

  // Layer 2: Translation (skip if English or unsupported language)
  if (!isEnglish && deeplLang) {
    const translation  = await translateToEnglish(text, deeplLang);
    translatedText     = translation.translated;
    translationMeta    = { service: translation.service, source_language: langResult.code, deepl_lang: deeplLang, char_count: translation.char_count };
  } else if (!isEnglish && !deeplLang) {
    translationMeta.service = 'unsupported_language';
    console.info(`[Multilingual] Language ${langResult.code} (${langResult.name}) not supported by DeepL — skipping translation`);
  }

  // Layer 3: NER on translated text
  const entities = extractNamedEntities(translatedText);

  return {
    ...finding,
    translated_snippet: translatedText !== text ? translatedText.slice(0, 500) : undefined,
    multilingual: {
      source_language:      langResult.code,
      source_language_name: langResult.name,
      language_confidence:  langResult.confidence,
      translated:           translatedText !== text,
      translation:          translationMeta,
      entities,
    },
  };
}

/**
 * processFindings — batch process an array of dark web findings.
 *
 * @param {object[]} findings
 * @returns {Promise<object[]>}
 */
async function processFindings(findings) {
  if (!FEATURE_ENABLED) {
    return findings.map(f => ({ ...f, multilingual: { skipped: true } }));
  }

  const results = [];
  for (const finding of findings) {
    try {
      results.push(await processFinding(finding));
    } catch (err) {
      console.error('[Multilingual] processFinding error:', err.message);
      results.push({ ...finding, multilingual: { error: err.message } });
    }
    // Small delay to respect DeepL rate limits
    await new Promise(r => setTimeout(r, 200));
  }
  return results;
}

module.exports = {
  detectLanguage,
  translateToEnglish,
  extractNamedEntities,
  processFinding,
  processFindings,
  LANGUAGE_NAMES,
  FRANC_TO_DEEPL,
};
