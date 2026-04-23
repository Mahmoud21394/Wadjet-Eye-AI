/**
 * ETI-AARE Email Parser Engine v1.0
 * Deep email parsing: headers, body, URLs, attachments, auth results
 * Supports .eml, .msg, raw MIME, Microsoft Graph, Gmail API formats
 */

'use strict';

const crypto = require('crypto');

// ─── Regex Arsenal ─────────────────────────────────────────────────────────
const URL_REGEX = /https?:\/\/(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:\/[^\s"'<>\]]*)?/gi;
const IP_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const EMAIL_REGEX = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
const BASE64_REGEX = /^[A-Za-z0-9+/]{20,}={0,2}$/;
const HOMOGRAPH_SUSPICIOUS = /[^\x00-\x7F]/; // non-ASCII in domain

// Unicode lookalike map (homograph detection)
const HOMOGRAPH_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
  'ϲ': 'c', 'ο': 'o', 'ν': 'v', 'ɑ': 'a', 'ɡ': 'g', 'ρ': 'p',
  '0': 'o', '1': 'l', '5': 's', '3': 'e'
};

// Known phishing TLD patterns
const SUSPICIOUS_TLDS = new Set([
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
  '.online', '.site', '.website', '.link', '.click', '.download',
  '.zip', '.mov', '.info', '.biz', '.pw', '.cc'
]);

// Attachment mime types by threat level
const ATTACHMENT_THREAT_LEVELS = {
  critical: new Set(['application/x-executable', 'application/x-dosexec', 'application/x-msdownload',
    'application/vnd.microsoft.portable-executable', 'application/x-sh', 'application/x-bat',
    'application/x-msdos-program']),
  high: new Set(['application/javascript', 'application/x-javascript', 'text/javascript',
    'application/x-powershell', 'application/vnd.ms-office', 'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/pdf', 'application/zip', 'application/x-rar-compressed',
    'application/x-7z-compressed', 'application/x-iso9660-image']),
  medium: new Set(['text/html', 'application/xhtml+xml', 'application/xml',
    'application/x-shockwave-flash', 'application/java-archive']),
  low: new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp',
    'text/plain', 'text/csv'])
};

// Extension threat map
const EXT_THREAT_MAP = {
  exe: 'critical', dll: 'critical', scr: 'critical', bat: 'critical',
  cmd: 'critical', com: 'critical', pif: 'critical', vbs: 'critical',
  vbe: 'critical', js: 'critical', jse: 'critical', ws: 'critical',
  wsh: 'critical', ps1: 'high', psm1: 'high', ps1xml: 'high',
  doc: 'high', docx: 'high', docm: 'high', xls: 'high', xlsx: 'high',
  xlsm: 'high', ppt: 'high', pptx: 'high', pptm: 'high',
  pdf: 'high', zip: 'high', rar: 'high', '7z': 'high',
  iso: 'high', img: 'high', lnk: 'high', hta: 'high',
  html: 'medium', htm: 'medium', xml: 'medium', svg: 'medium'
};

// ─── Header Authentication Parser ──────────────────────────────────────────
class AuthHeaderParser {
  /**
   * Parse Authentication-Results header
   * Returns structured SPF, DKIM, DMARC results
   */
  static parseAuthResults(header) {
    if (!header) return { spf: 'none', dkim: 'none', dmarc: 'none', raw: null };
    const h = Array.isArray(header) ? header.join(' ') : header;
    return {
      spf: this._extractResult(h, 'spf'),
      dkim: this._extractResult(h, 'dkim'),
      dmarc: this._extractResult(h, 'dmarc'),
      arc: this._extractResult(h, 'arc'),
      raw: h
    };
  }

  static _extractResult(text, proto) {
    const re = new RegExp(`${proto}\\s*=\\s*(pass|fail|softfail|neutral|none|permerror|temperror|hardfail)`, 'i');
    const m = text.match(re);
    return m ? m[1].toLowerCase() : 'none';
  }

  /**
   * Parse Received headers to build hop-by-hop relay chain
   */
  static parseReceivedChain(receivedHeaders) {
    if (!receivedHeaders) return [];
    const headers = Array.isArray(receivedHeaders) ? receivedHeaders : [receivedHeaders];
    return headers.map((h, idx) => {
      const hop = { index: idx, raw: h };

      // Extract FROM
      const fromMatch = h.match(/from\s+([^\s]+)\s+\(([^)]+)\)/i);
      if (fromMatch) {
        hop.from_hostname = fromMatch[1];
        hop.from_info = fromMatch[2];
        const ipMatch = fromMatch[2].match(IP_REGEX);
        hop.from_ip = ipMatch ? ipMatch[0] : null;
      }

      // Extract BY
      const byMatch = h.match(/by\s+([^\s]+)/i);
      if (byMatch) hop.by_hostname = byMatch[1];

      // Extract timestamp
      const timeMatch = h.match(/;\s*(.+)$/);
      if (timeMatch) {
        try { hop.timestamp = new Date(timeMatch[1].trim()).toISOString(); }
        catch { hop.timestamp = timeMatch[1].trim(); }
      }

      // Flag suspicious hops
      hop.suspicious = this._isHopSuspicious(hop);
      return hop;
    });
  }

  static _isHopSuspicious(hop) {
    if (!hop.from_hostname) return false;
    const hostname = hop.from_hostname.toLowerCase();
    // Dynamic IP pattern (suspicious sender)
    if (/\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}/.test(hostname)) return true;
    // Suspicious TLD
    for (const tld of SUSPICIOUS_TLDS) {
      if (hostname.endsWith(tld)) return true;
    }
    // Mismatched PTR/HELO
    if (hop.from_hostname && hop.from_ip) {
      if (hostname.includes('unknown') || hostname.includes('localhost')) return true;
    }
    return false;
  }

  /**
   * Validate SPF alignment between From domain and SPF pass domain
   */
  static validateSpfAlignment(fromAddress, receivedSpf) {
    if (!fromAddress || !receivedSpf) return { aligned: false, reason: 'missing_data' };
    const fromDomain = fromAddress.split('@')[1]?.toLowerCase() || '';
    const spfDomainMatch = receivedSpf.match(/envelope-from=([^\s;]+)/i);
    const spfDomain = spfDomainMatch ? spfDomainMatch[1].split('@')[1]?.toLowerCase() || '' : '';

    if (!spfDomain) return { aligned: false, reason: 'no_envelope_from' };

    // Strict alignment
    if (fromDomain === spfDomain) return { aligned: true, mode: 'strict' };
    // Relaxed alignment (organizational domain match)
    const fromOrg = fromDomain.split('.').slice(-2).join('.');
    const spfOrg = spfDomain.split('.').slice(-2).join('.');
    if (fromOrg === spfOrg) return { aligned: true, mode: 'relaxed' };

    return { aligned: false, reason: 'domain_mismatch', from_domain: fromDomain, spf_domain: spfDomain };
  }
}

// ─── URL De-obfuscation & Analysis ─────────────────────────────────────────
class URLAnalyzer {
  static deobfuscate(url) {
    if (!url) return { original: url, deobfuscated: url, techniques: [] };
    let deob = url;
    const techniques = [];

    // URL encoding
    if (/%[0-9A-Fa-f]{2}/.test(deob)) {
      try { deob = decodeURIComponent(deob); techniques.push('url_encoded'); } catch {}
    }

    // HTML entities
    if (/&amp;|&lt;|&gt;|&#\d+;/.test(deob)) {
      deob = deob.replace(/&amp;/g, '&').replace(/&lt;/g, '<')
                 .replace(/&gt;/g, '>').replace(/&#(\d+);/g, (_, c) => String.fromCharCode(c));
      techniques.push('html_entity_encoded');
    }

    // Redirect services
    const redirectPatterns = [
      /safelinks\.protection\.outlook\.com.*url=([^&]+)/i,
      /urldefense\.com\/v3\/__([^;]+)/i,
      /l\.facebook\.com\/l\.php\?u=([^&]+)/i,
      /t\.co\/(\w+)/i,
      /bit\.ly\/(\w+)/i,
      /ow\.ly\/(\w+)/i
    ];
    for (const pattern of redirectPatterns) {
      const m = deob.match(pattern);
      if (m && m[1]) {
        try {
          const inner = decodeURIComponent(m[1]);
          if (inner.startsWith('http')) { deob = inner; techniques.push('redirect_service'); break; }
        } catch {}
      }
    }

    // IP-based URL detection
    const ipUrl = deob.match(/https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);
    if (ipUrl) techniques.push('ip_url');

    // Port in URL
    if (/:\d{4,5}\//.test(deob)) techniques.push('nonstandard_port');

    // Subdomain depth
    try {
      const urlObj = new URL(deob);
      const parts = urlObj.hostname.split('.');
      if (parts.length > 4) techniques.push('excessive_subdomains');

      // Homograph detection
      if (HOMOGRAPH_SUSPICIOUS.test(urlObj.hostname)) techniques.push('homograph_domain');
    } catch {}

    return { original: url, deobfuscated: deob, techniques, is_suspicious: techniques.length > 0 };
  }

  static extractUrls(text) {
    if (!text) return [];
    const found = new Set();
    let m;
    URL_REGEX.lastIndex = 0;
    while ((m = URL_REGEX.exec(text)) !== null) {
      found.add(m[0]);
    }
    return [...found].map(url => this.deobfuscate(url));
  }

  static assessDomain(domain) {
    if (!domain) return { risk: 'unknown' };
    const d = domain.toLowerCase();
    const assessment = { domain: d, risk: 'low', flags: [] };

    // Suspicious TLD
    for (const tld of SUSPICIOUS_TLDS) {
      if (d.endsWith(tld)) { assessment.flags.push('suspicious_tld'); assessment.risk = 'high'; }
    }

    // Newly registered pattern (many numbers/random chars)
    if (/[a-z]{2,5}\d{4,}/.test(d)) { assessment.flags.push('likely_dga'); assessment.risk = 'high'; }

    // DGA detection (high consonant ratio)
    const vowels = (d.match(/[aeiou]/g) || []).length;
    const consonants = (d.match(/[bcdfghjklmnpqrstvwxyz]/g) || []).length;
    if (consonants > 0 && vowels / consonants < 0.2 && d.length > 8) {
      assessment.flags.push('possible_dga'); assessment.risk = 'high';
    }

    // Lookalike domain (brand impersonation)
    const brands = ['microsoft', 'google', 'apple', 'paypal', 'amazon', 'facebook',
                    'linkedin', 'twitter', 'instagram', 'netflix', 'chase', 'wellsfargo',
                    'bankofamerica', 'office365', 'onedrive', 'sharepoint', 'outlook'];
    for (const brand of brands) {
      if (d.includes(brand) && !d.endsWith(`.${brand}.com`)) {
        assessment.flags.push(`lookalike_${brand}`);
        assessment.risk = 'critical';
      }
    }

    // Homograph check
    let normalized = '';
    for (const ch of d) { normalized += HOMOGRAPH_MAP[ch] || ch; }
    if (normalized !== d) { assessment.flags.push('homograph'); assessment.risk = 'critical'; }

    return assessment;
  }
}

// ─── Attachment Analyzer ────────────────────────────────────────────────────
class AttachmentAnalyzer {
  static analyze(attachment) {
    const result = {
      filename: attachment.filename || 'unknown',
      content_type: attachment.contentType || attachment.content_type || 'application/octet-stream',
      size: attachment.size || 0,
      sha256: null,
      md5: null,
      threat_level: 'unknown',
      flags: [],
      extension: null
    };

    // Hash computation
    if (attachment.content || attachment.data) {
      const data = attachment.content || attachment.data;
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'base64');
      result.sha256 = crypto.createHash('sha256').update(buf).digest('hex');
      result.md5 = crypto.createHash('md5').update(buf).digest('hex');
      result.size = buf.length;
    }

    // Extension detection (double-extension attack)
    const ext = result.filename.split('.').pop()?.toLowerCase();
    result.extension = ext;
    const allExts = result.filename.split('.').slice(1).map(e => e.toLowerCase());
    if (allExts.length > 1) {
      const lastExt = allExts[allExts.length - 1];
      const secondLastExt = allExts[allExts.length - 2];
      const deceptiveExts = new Set(['pdf', 'docx', 'xlsx', 'jpg', 'png', 'txt']);
      const execExts = new Set(Object.keys(EXT_THREAT_MAP).filter(k => EXT_THREAT_MAP[k] === 'critical'));
      if (deceptiveExts.has(secondLastExt) && execExts.has(lastExt)) {
        result.flags.push('double_extension_attack');
      }
    }

    // Threat level from extension
    if (ext && EXT_THREAT_MAP[ext]) {
      result.threat_level = EXT_THREAT_MAP[ext];
    }

    // Threat level from MIME type
    for (const [level, mimes] of Object.entries(ATTACHMENT_THREAT_LEVELS)) {
      if (mimes.has(result.content_type)) {
        if (!result.threat_level || this._levelValue(level) > this._levelValue(result.threat_level)) {
          result.threat_level = level;
        }
      }
    }

    // MIME/extension mismatch (masquerading)
    if (ext === 'pdf' && !result.content_type.includes('pdf')) result.flags.push('mime_extension_mismatch');
    if (ext === 'docx' && !result.content_type.includes('word')) result.flags.push('mime_extension_mismatch');

    // Suspicious filename patterns
    const suspiciousPatterns = [
      /invoice/i, /payment/i, /receipt/i, /order/i, /urgent/i,
      /account/i, /verify/i, /confirm/i, /statement/i, /document/i
    ];
    for (const p of suspiciousPatterns) {
      if (p.test(result.filename)) { result.flags.push('social_engineering_filename'); break; }
    }

    // Password-protected (can't scan)
    if (result.filename.match(/password|protected|encrypted/i)) result.flags.push('possibly_encrypted');

    return result;
  }

  static _levelValue(level) {
    return { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 }[level] || 0;
  }
}

// ─── Body Analyzer ──────────────────────────────────────────────────────────
class BodyAnalyzer {
  static analyze(body, contentType = 'text/plain') {
    const result = {
      text: '',
      html: '',
      urls: [],
      emails: [],
      ips: [],
      phone_numbers: [],
      urgency_score: 0,
      social_engineering_flags: [],
      obfuscation_detected: false
    };

    // Decode HTML if needed
    if (contentType.includes('html')) {
      result.html = body;
      result.text = this._htmlToText(body);
    } else {
      result.text = body;
    }

    const text = result.text + ' ' + result.html;

    // Extract URLs (from both text and HTML)
    const htmlUrls = this._extractHtmlUrls(result.html);
    const textUrls = URLAnalyzer.extractUrls(text);
    const allUrls = new Map();
    for (const u of [...htmlUrls, ...textUrls]) {
      allUrls.set(u.deobfuscated, u);
    }
    result.urls = [...allUrls.values()];

    // Extract emails
    result.emails = [...new Set((text.match(EMAIL_REGEX) || []))];

    // Extract IPs
    result.ips = [...new Set((text.match(IP_REGEX) || []))].filter(ip =>
      !ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('172.'));

    // Phone numbers
    const phoneRegex = /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;
    result.phone_numbers = [...new Set((text.match(phoneRegex) || []))];

    // Social engineering analysis
    result.social_engineering_flags = this._detectSocialEngineering(text);
    result.urgency_score = this._calcUrgencyScore(text);

    // Obfuscation detection
    result.obfuscation_detected = this._detectObfuscation(result.html);

    // Hidden text detection
    result.hidden_content = this._detectHiddenContent(result.html);

    return result;
  }

  static _htmlToText(html) {
    if (!html) return '';
    return html
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/\s+/g, ' ')
      .trim();
  }

  static _extractHtmlUrls(html) {
    if (!html) return [];
    const urls = [];
    const hrefRegex = /href=["']([^"']+)["']/gi;
    const srcRegex = /src=["']([^"']+)["']/gi;
    let m;
    while ((m = hrefRegex.exec(html)) !== null) {
      if (m[1].startsWith('http')) urls.push(URLAnalyzer.deobfuscate(m[1]));
    }
    while ((m = srcRegex.exec(html)) !== null) {
      if (m[1].startsWith('http')) urls.push(URLAnalyzer.deobfuscate(m[1]));
    }
    return urls;
  }

  static _detectSocialEngineering(text) {
    const flags = [];
    const t = text.toLowerCase();

    const patterns = [
      { flag: 'urgency', words: ['urgent', 'immediate', 'action required', 'expires', 'deadline', 'last chance', 'act now', 'asap'] },
      { flag: 'authority_impersonation', words: ['ceo', 'cfo', 'cto', 'president', 'director', 'manager', 'your bank', 'irs', 'fbi', 'police'] },
      { flag: 'fear_tactics', words: ['suspended', 'compromised', 'hacked', 'unauthorized', 'verify immediately', 'account locked', 'unusual activity'] },
      { flag: 'financial_lure', words: ['wire transfer', 'payment', 'invoice', 'refund', 'compensation', 'prize', 'lottery', 'inheritance', 'unclaimed funds'] },
      { flag: 'credential_harvesting', words: ['click here', 'sign in', 'log in', 'verify your', 'confirm your', 'update your', 'enter your password', 'validate'] },
      { flag: 'bec_pattern', words: ['gift card', 'purchase gift', 'keep confidential', 'do not reply to others', 'wire funds', 'new banking', 'change payment'] },
    ];

    for (const { flag, words } of patterns) {
      const matched = words.filter(w => t.includes(w));
      if (matched.length > 0) flags.push({ flag, matched_terms: matched });
    }

    return flags;
  }

  static _calcUrgencyScore(text) {
    const t = text.toLowerCase();
    let score = 0;
    const urgencyWords = {
      'urgent': 20, 'immediately': 20, 'right away': 15, 'asap': 15,
      'expires in': 15, 'last chance': 15, 'act now': 20, 'within 24': 15,
      'within 48': 10, 'deadline': 10, 'suspended': 20, 'verify now': 20,
      'account locked': 20, 'unusual activity': 15
    };
    for (const [word, pts] of Object.entries(urgencyWords)) {
      if (t.includes(word)) score += pts;
    }
    return Math.min(score, 100);
  }

  static _detectObfuscation(html) {
    if (!html) return false;
    // CSS color tricks (white text on white background)
    if (/color:\s*#(?:fff|ffffff|white)/i.test(html) && /font-size:\s*[01]px/i.test(html)) return true;
    // Zero-size elements
    if (/(?:height|width)\s*:\s*0(?:px)?/i.test(html)) return true;
    // Hidden div
    if (/display\s*:\s*none/i.test(html)) return true;
    // Text direction tricks
    if (/direction\s*:\s*rtl/i.test(html) && /unicode-bidi/i.test(html)) return true;
    return false;
  }

  static _detectHiddenContent(html) {
    if (!html) return null;
    const hiddenItems = [];
    // Hidden input fields
    const hiddenInputs = html.match(/<input[^>]+type=["']hidden["'][^>]*>/gi) || [];
    hiddenInputs.forEach(i => hiddenItems.push({ type: 'hidden_input', raw: i }));
    // Invisible elements
    if (/visibility\s*:\s*hidden/i.test(html)) hiddenItems.push({ type: 'visibility_hidden' });
    if (/opacity\s*:\s*0/i.test(html)) hiddenItems.push({ type: 'zero_opacity' });
    return hiddenItems.length > 0 ? hiddenItems : null;
  }
}

// ─── Main Email Parser ───────────────────────────────────────────────────────
class EmailParser {
  /**
   * Parse a raw email object (from any source) into a unified EmailIntelligence record
   */
  static parse(rawEmail, source = 'manual') {
    const parsed = {
      message_id: null,
      source,
      received_at: new Date().toISOString(),
      headers: {},
      auth: {},
      routing: {},
      sender: {},
      recipients: {},
      subject: '',
      body: {},
      attachments: [],
      urls: [],
      indicators: { ips: [], domains: [], urls: [], hashes: [], emails: [] },
      threat_signals: [],
      raw_size: 0
    };

    try {
      // ── Headers ──
      const h = rawEmail.headers || rawEmail.internetMessageHeaders || {};
      parsed.headers = this._normalizeHeaders(h);
      parsed.message_id = parsed.headers['message-id'] || rawEmail.id || rawEmail.internetMessageId || this._generateId();

      // ── Auth Results ──
      parsed.auth = AuthHeaderParser.parseAuthResults(parsed.headers['authentication-results']);
      parsed.auth.spf_alignment = AuthHeaderParser.validateSpfAlignment(
        parsed.headers['from'],
        parsed.headers['received-spf']
      );
      parsed.auth.received_spf_raw = parsed.headers['received-spf'];
      parsed.auth.dkim_signature = !!parsed.headers['dkim-signature'];

      // ── Routing ──
      const receivedHeaders = this._getMultiHeader(h, 'received');
      parsed.routing.hops = AuthHeaderParser.parseReceivedChain(receivedHeaders);
      parsed.routing.hop_count = parsed.routing.hops.length;
      parsed.routing.suspicious_hops = parsed.routing.hops.filter(h => h.suspicious).length;
      parsed.routing.originating_ip = parsed.routing.hops.length > 0
        ? parsed.routing.hops[parsed.routing.hops.length - 1]?.from_ip
        : null;

      // ── Sender Analysis ──
      const fromHeader = parsed.headers['from'] || rawEmail.from?.emailAddress?.address || '';
      parsed.sender = this._parseSender(fromHeader);
      parsed.sender.reply_to = parsed.headers['reply-to'];
      parsed.sender.return_path = parsed.headers['return-path'];
      parsed.sender.x_mailer = parsed.headers['x-mailer'];
      parsed.sender.x_originating_ip = parsed.headers['x-originating-ip'];

      // Sender anomalies
      parsed.sender.anomalies = this._detectSenderAnomalies(parsed);

      // ── Recipients ──
      parsed.recipients = {
        to: this._parseAddressList(parsed.headers['to'] || rawEmail.toRecipients),
        cc: this._parseAddressList(parsed.headers['cc'] || rawEmail.ccRecipients),
        bcc: this._parseAddressList(parsed.headers['bcc'] || rawEmail.bccRecipients)
      };

      // ── Subject ──
      parsed.subject = rawEmail.subject || parsed.headers['subject'] || '';
      parsed.subject_analysis = this._analyzeSubject(parsed.subject);

      // ── Body ──
      const bodyContent = rawEmail.body?.content || rawEmail.bodyPreview || rawEmail.snippet || '';
      const bodyType = rawEmail.body?.contentType || 'text/plain';
      parsed.body = BodyAnalyzer.analyze(bodyContent, bodyType);

      // ── Attachments ──
      const attachments = rawEmail.attachments || rawEmail.hasAttachments ? (rawEmail.attachments || []) : [];
      parsed.attachments = attachments.map(a => AttachmentAnalyzer.analyze(a));

      // ── Consolidated Indicators ──
      parsed.indicators = this._extractIndicators(parsed);

      // ── Threat Signals ──
      parsed.threat_signals = this._generateThreatSignals(parsed);

      // ── Domain Analysis ──
      parsed.domain_analysis = this._analyzeDomains(parsed);

      parsed.raw_size = JSON.stringify(rawEmail).length;
    } catch (err) {
      parsed.parse_error = err.message;
    }

    return parsed;
  }

  static _normalizeHeaders(headers) {
    if (Array.isArray(headers)) {
      // MS Graph format: [{name, value}]
      return headers.reduce((acc, h) => {
        acc[h.name?.toLowerCase()] = h.value;
        return acc;
      }, {});
    }
    if (typeof headers === 'object') {
      const norm = {};
      for (const [k, v] of Object.entries(headers)) {
        norm[k.toLowerCase()] = v;
      }
      return norm;
    }
    return {};
  }

  static _getMultiHeader(headers, name) {
    // Some parsers return arrays for multi-value headers
    if (Array.isArray(headers)) {
      return headers.filter(h => h.name?.toLowerCase() === name).map(h => h.value);
    }
    const val = headers[name] || headers[name.toLowerCase()];
    return Array.isArray(val) ? val : val ? [val] : [];
  }

  static _parseSender(fromHeader) {
    if (!fromHeader) return { raw: '', display_name: '', address: '', domain: '' };
    const match = fromHeader.match(/^(.+?)\s*<([^>]+)>$/) || fromHeader.match(/^<?([^>]+)>?$/);
    const address = match ? (match[2] || match[1] || '').trim() : fromHeader.trim();
    const domain = address.includes('@') ? address.split('@')[1]?.toLowerCase() : '';
    const display_name = match && match[2] ? match[1].trim().replace(/^["']|["']$/g, '') : '';
    return { raw: fromHeader, display_name, address, domain };
  }

  static _parseAddressList(addresses) {
    if (!addresses) return [];
    if (Array.isArray(addresses)) {
      return addresses.map(a => {
        if (typeof a === 'string') return this._parseSender(a);
        if (a.emailAddress) return this._parseSender(a.emailAddress.address);
        return a;
      });
    }
    if (typeof addresses === 'string') {
      return addresses.split(',').map(a => this._parseSender(a.trim()));
    }
    return [];
  }

  static _analyzeSubject(subject) {
    if (!subject) return { risk: 'low', flags: [] };
    const flags = [];
    const s = subject.toLowerCase();

    // RE: FW: prefix manipulation
    if (/^(?:re:|fw:|fwd:)\s*(?:re:|fw:|fwd:)/i.test(subject)) flags.push('fake_reply_forward');

    // ALL CAPS urgency
    if (subject === subject.toUpperCase() && subject.length > 5) flags.push('all_caps');

    // Excessive punctuation
    if (/[!?]{2,}/.test(subject)) flags.push('excessive_punctuation');

    // Suspicious keywords
    const keywords = ['verify', 'action required', 'urgent', 'password', 'account', 'suspended',
      'invoice', 'payment', 'wire', 'gift card', 'prize', 'winner', 'congratulations',
      'security alert', 'unusual activity', 'click here', 'confirm'];
    const matched = keywords.filter(k => s.includes(k));
    if (matched.length > 0) flags.push({ flag: 'suspicious_keywords', terms: matched });

    // Brand impersonation
    const brands = ['microsoft', 'google', 'apple', 'paypal', 'amazon', 'netflix', 'linkedin',
      'dropbox', 'onedrive', 'office 365', 'outlook', 'sharepoint'];
    const brandMatched = brands.filter(b => s.includes(b));
    if (brandMatched.length > 0) flags.push({ flag: 'brand_impersonation', brands: brandMatched });

    const risk = flags.length >= 3 ? 'high' : flags.length >= 1 ? 'medium' : 'low';
    return { risk, flags };
  }

  static _detectSenderAnomalies(parsed) {
    const anomalies = [];
    const { sender, auth, headers } = parsed;

    // Display name ≠ actual domain (common BEC/phishing)
    if (sender.display_name && sender.address) {
      const brandInDisplay = ['microsoft', 'google', 'apple', 'paypal', 'amazon'].find(b =>
        sender.display_name.toLowerCase().includes(b));
      if (brandInDisplay && !sender.domain?.includes(brandInDisplay)) {
        anomalies.push({ type: 'display_name_domain_mismatch', brand: brandInDisplay });
      }
    }

    // From ≠ Reply-To (BEC indicator)
    if (sender.reply_to && sender.address && sender.reply_to !== sender.address) {
      const replyDomain = sender.reply_to.split('@')[1]?.toLowerCase();
      if (replyDomain !== sender.domain) {
        anomalies.push({ type: 'from_reply_to_domain_mismatch', from: sender.domain, reply_to: replyDomain });
      }
    }

    // Auth failures
    if (auth.spf === 'fail') anomalies.push({ type: 'spf_fail' });
    if (auth.spf === 'softfail') anomalies.push({ type: 'spf_softfail' });
    if (auth.dkim === 'fail') anomalies.push({ type: 'dkim_fail' });
    if (auth.dmarc === 'fail') anomalies.push({ type: 'dmarc_fail' });
    if (auth.spf === 'none' && auth.dkim === 'none') anomalies.push({ type: 'no_authentication' });

    // Suspicious X-Mailer (bulk mailer, spoofing tools)
    const suspiciousMailers = ['phpmailer', 'sendgrid', 'mass mailer', 'bullet', 'bomber'];
    if (sender.x_mailer) {
      const xm = sender.x_mailer.toLowerCase();
      for (const sm of suspiciousMailers) {
        if (xm.includes(sm)) anomalies.push({ type: 'suspicious_mailer', mailer: sender.x_mailer });
      }
    }

    // Free email service used for business communication
    const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com', 'tutanota.com'];
    if (sender.domain && freeProviders.includes(sender.domain)) {
      anomalies.push({ type: 'free_email_provider', provider: sender.domain });
    }

    return anomalies;
  }

  static _extractIndicators(parsed) {
    const indicators = { ips: new Set(), domains: new Set(), urls: new Set(), hashes: new Set(), emails: new Set() };

    // IPs from routing
    parsed.routing.hops.forEach(h => { if (h.from_ip) indicators.ips.add(h.from_ip); });
    if (parsed.sender.x_originating_ip) indicators.ips.add(parsed.sender.x_originating_ip);
    if (parsed.routing.originating_ip) indicators.ips.add(parsed.routing.originating_ip);

    // Domains
    if (parsed.sender.domain) indicators.domains.add(parsed.sender.domain);
    if (parsed.sender.reply_to) {
      const d = parsed.sender.reply_to.split('@')[1];
      if (d) indicators.domains.add(d.toLowerCase());
    }

    // URLs
    parsed.body.urls.forEach(u => {
      indicators.urls.add(u.deobfuscated);
      try {
        const urlObj = new URL(u.deobfuscated);
        indicators.domains.add(urlObj.hostname);
      } catch {}
    });

    // Hashes from attachments
    parsed.attachments.forEach(a => {
      if (a.sha256) indicators.hashes.add(a.sha256);
      if (a.md5) indicators.hashes.add(a.md5);
    });

    // Emails
    parsed.body.emails.forEach(e => indicators.emails.add(e));

    return {
      ips: [...indicators.ips],
      domains: [...indicators.domains],
      urls: [...indicators.urls],
      hashes: [...indicators.hashes],
      emails: [...indicators.emails]
    };
  }

  static _generateThreatSignals(parsed) {
    const signals = [];

    // Auth failures
    const authScore = (parsed.auth.spf === 'fail' ? 2 : 0) +
                      (parsed.auth.dkim === 'fail' ? 2 : 0) +
                      (parsed.auth.dmarc === 'fail' ? 3 : 0);
    if (authScore >= 3) {
      signals.push({ type: 'auth_failure', severity: 'high', score: authScore * 10,
        detail: `SPF:${parsed.auth.spf} DKIM:${parsed.auth.dkim} DMARC:${parsed.auth.dmarc}` });
    }

    // Suspicious routing
    if (parsed.routing.suspicious_hops > 0) {
      signals.push({ type: 'suspicious_routing', severity: 'medium', score: 25,
        detail: `${parsed.routing.suspicious_hops} suspicious relay hops` });
    }

    // Sender anomalies
    parsed.sender.anomalies.forEach(a => {
      const sev = a.type.includes('mismatch') || a.type.includes('fail') ? 'high' : 'medium';
      signals.push({ type: `sender_anomaly_${a.type}`, severity: sev, score: 20, detail: JSON.stringify(a) });
    });

    // Subject risks
    if (parsed.subject_analysis?.risk === 'high') {
      signals.push({ type: 'suspicious_subject', severity: 'medium', score: 20,
        detail: parsed.subject_analysis.flags.join(', ') });
    }

    // Social engineering
    if (parsed.body.social_engineering_flags?.length > 0) {
      signals.push({ type: 'social_engineering', severity: 'high', score: 30,
        detail: parsed.body.social_engineering_flags.map(f => f.flag || f).join(', ') });
    }

    // High urgency
    if (parsed.body.urgency_score > 40) {
      signals.push({ type: 'high_urgency', severity: 'medium', score: parsed.body.urgency_score / 2,
        detail: `Urgency score: ${parsed.body.urgency_score}` });
    }

    // Critical attachments
    parsed.attachments.forEach(a => {
      if (a.threat_level === 'critical') {
        signals.push({ type: 'critical_attachment', severity: 'critical', score: 50,
          detail: `${a.filename} (${a.content_type})` });
      } else if (a.threat_level === 'high') {
        signals.push({ type: 'high_risk_attachment', severity: 'high', score: 35,
          detail: `${a.filename} (${a.content_type})` });
      }
    });

    // Obfuscation
    if (parsed.body.obfuscation_detected) {
      signals.push({ type: 'body_obfuscation', severity: 'high', score: 30,
        detail: 'HTML content obfuscation techniques detected' });
    }

    // Suspicious URLs
    const suspUrls = (parsed.body.urls || []).filter(u => u.is_suspicious);
    if (suspUrls.length > 0) {
      signals.push({ type: 'suspicious_urls', severity: 'high', score: 40,
        detail: `${suspUrls.length} suspicious URLs: ${suspUrls[0].deobfuscated}` });
    }

    return signals;
  }

  static _analyzeDomains(parsed) {
    const domains = parsed.indicators.domains.map(d => URLAnalyzer.assessDomain(d));
    return {
      all: domains,
      high_risk: domains.filter(d => d.risk === 'high' || d.risk === 'critical'),
      lookalike_count: domains.filter(d => d.flags.some(f => f.toString().startsWith('lookalike'))).length
    };
  }

  static _generateId() {
    return `<eti-${Date.now()}-${Math.random().toString(36).slice(2)}@raykan.local>`;
  }
}

module.exports = { EmailParser, URLAnalyzer, AttachmentAnalyzer, BodyAnalyzer, AuthHeaderParser };
