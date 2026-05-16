/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Adversary DNA Fingerprinting System  v1.0
 *  backend/services/intelligence/adversary-dna.js
 *
 *  INNOVATION-001: Adversary DNA Fingerprinting
 *  ─────────────────────────────────────────────
 *  Encodes observed adversary behaviour into a structured "DNA"
 *  fingerprint that persists across campaigns and enables:
 *
 *  1. Attribution — match new incidents to known threat actors by
 *     comparing DNA similarity (cosine similarity on TTP vectors)
 *
 *  2. Campaign clustering — group geographically/temporally related
 *     incidents by DNA proximity in Pinecone vector space
 *
 *  3. Predictive hunting — generate hunting hypotheses based on
 *     historically observed DNA patterns for a given actor
 *
 *  DNA Components (4-vector architecture):
 *  ────────────────────────────────────────
 *  • TTP Vector (256-dim):
 *      One-hot + frequency-weighted encoding of MITRE ATT&CK
 *      technique IDs observed across all incidents.
 *      Index = deterministic hash(technique_id) % 256.
 *
 *  • Temporal Vector (168-dim, 24h × 7d):
 *      Activity heatmap — which hour-of-day + day-of-week the actor
 *      is most active, normalised to [0, 1].
 *
 *  • Infrastructure Fingerprint (64-dim):
 *      Encodes C2 ASN diversity, TLD distribution, registrar
 *      patterns, hosting provider clustering, and IP range reuse.
 *
 *  • Toolchain Signature (128-dim):
 *      Encodes observed malware families, packers, obfuscation
 *      techniques, PE characteristics, and YARA rule matches.
 *
 *  Combined DNA vector = concat(TTP, Temporal, Infra, Toolchain)
 *  → 616 dimensions total → stored in Pinecone namespace 'adversary-dna'
 *
 *  Feature flags:
 *    FEATURE_ADVERSARY_DNA=true — enable this system
 *
 *  Required env vars:
 *    PINECONE_API_KEY, PINECONE_HOST — Pinecone vector store
 *    FEATURE_ADVERSARY_DNA           — feature flag (default: false)
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const crypto = require('crypto');
const https  = require('https');

// ── Feature flag ───────────────────────────────────────────────────
const FEATURE_ENABLED = process.env.FEATURE_ADVERSARY_DNA === 'true';

// ── DNA dimension constants ────────────────────────────────────────
const TTP_DIM       = 256;
const TEMPORAL_DIM  = 168; // 24 hours × 7 days
const INFRA_DIM     = 64;
const TOOLCHAIN_DIM = 128;
const DNA_DIMS      = TTP_DIM + TEMPORAL_DIM + INFRA_DIM + TOOLCHAIN_DIM; // 616

// ── Known MITRE ATT&CK technique → index mapping ──────────────────
// Deterministic hash: index = fnv32(technique_id) % TTP_DIM
function ttpIndex(techniqueId) {
  const id  = techniqueId.toUpperCase().replace(/[^A-Z0-9.]/g, '');
  let   h   = 2166136261;
  for (let i = 0; i < id.length; i++) {
    h ^= id.charCodeAt(i);
    h  = (h * 16777619) >>> 0;
  }
  return h % TTP_DIM;
}

// ── Known malware families → toolchain index ──────────────────────
const MALWARE_FAMILIES = [
  'cobalt_strike', 'metasploit', 'empire', 'sliver', 'brute_ratel',
  'emotet', 'trickbot', 'qbot', 'icedid', 'dridex',
  'mimikatz', 'lazagne', 'procdump', 'cobaltstrike_beacon',
  'havoc', 'nighthawk', 'poshc2', 'mythic', 'nighthawk',
  'donut', 'sgn', 'veil', 'shikata_ga_nai', 'peloader',
  'lockbit', 'alphv', 'hive', 'cl0p', 'play',
  'darkside', 'revil', 'conti', 'ryuk', 'maze',
];

function toolchainIndex(familyName) {
  const clean = familyName.toLowerCase().replace(/[^a-z0-9_]/g, '_');
  const idx   = MALWARE_FAMILIES.indexOf(clean);
  if (idx >= 0) return idx % TOOLCHAIN_DIM;
  // Unknown family — hash-based index in upper half of toolchain vector
  let h = 2166136261;
  for (let i = 0; i < clean.length; i++) { h ^= clean.charCodeAt(i); h = (h * 16777619) >>> 0; }
  return (h % (TOOLCHAIN_DIM / 2)) + TOOLCHAIN_DIM / 2;
}

// ─────────────────────────────────────────────────────────────────
//  DNA Builder
// ─────────────────────────────────────────────────────────────────

/**
 * buildTTPVector — encode MITRE ATT&CK TTPs into a 256-dim vector.
 *
 * @param {Array<{technique_id: string, count?: number}>} ttps
 * @returns {number[]} normalised 256-dim vector
 */
function buildTTPVector(ttps) {
  const vec = new Array(TTP_DIM).fill(0);

  for (const { technique_id, count = 1 } of ttps) {
    if (!technique_id) continue;
    // Handle sub-techniques: T1055.001 → also set T1055
    const idx = ttpIndex(technique_id);
    vec[idx]  = Math.min(vec[idx] + count, 100);

    const parentId = technique_id.split('.')[0];
    if (parentId !== technique_id) {
      const pidx  = ttpIndex(parentId);
      vec[pidx]   = Math.min(vec[pidx] + count * 0.5, 100);
    }
  }

  return l2Normalise(vec);
}

/**
 * buildTemporalVector — encode activity timing into 24h×7d heatmap (168-dim).
 *
 * @param {Array<{timestamp: string}>} events - Events with ISO timestamps
 * @returns {number[]} normalised 168-dim vector
 */
function buildTemporalVector(events) {
  const vec = new Array(TEMPORAL_DIM).fill(0);

  for (const { timestamp } of events) {
    if (!timestamp) continue;
    try {
      const d    = new Date(timestamp);
      const hour = d.getUTCHours();        // 0-23
      const day  = d.getUTCDay();          // 0=Sunday … 6=Saturday
      const idx  = day * 24 + hour;       // [0, 168)
      vec[idx]  += 1;
    } catch (_) {}
  }

  return l2Normalise(vec);
}

/**
 * buildInfraVector — encode infrastructure patterns into 64-dim vector.
 *
 * @param {object} infraData - { asns: string[], tlds: string[], registrars: string[], hosting: string[], ip_ranges: string[] }
 * @returns {number[]} normalised 64-dim vector
 */
function buildInfraVector(infraData) {
  const vec = new Array(INFRA_DIM).fill(0);
  const { asns = [], tlds = [], registrars = [], hosting = [], ip_ranges = [] } = infraData;

  // Encode ASN diversity (first 16 dims)
  for (const asn of asns.slice(0, 16)) {
    const idx = (parseInt(asn.replace(/\D/g, ''), 10) || 0) % 16;
    vec[idx] += 1;
  }

  // Encode TLD distribution (dims 16-31)
  const TOP_TLDS = ['.com', '.net', '.org', '.io', '.ru', '.cn', '.onion', '.top', '.xyz', '.info', '.biz', '.co', '.uk', '.de', '.fr', '.nl'];
  for (const tld of tlds) {
    const idx = TOP_TLDS.indexOf(tld.toLowerCase());
    if (idx >= 0) vec[16 + idx] += 1;
    else { let h = 2166136261; for (let i = 0; i < tld.length; i++) { h ^= tld.charCodeAt(i); h = (h * 16777619) >>> 0; } vec[30 + h % 2] += 1; }
  }

  // Encode registrar patterns (dims 32-47)
  const KNOWN_REGISTRARS = ['namecheap', 'godaddy', 'networksolutions', 'tucows', 'enom', 'regru', 'reg.ru', 'pananames', 'danesco'];
  for (const reg of registrars) {
    const rl = reg.toLowerCase();
    const idx = KNOWN_REGISTRARS.findIndex(r => rl.includes(r));
    vec[32 + (idx >= 0 ? idx : 8)] += 1;
  }

  // Encode hosting providers (dims 48-63)
  const KNOWN_HOSTS = ['aws', 'azure', 'gcp', 'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner', 'choopa', 'constantia'];
  for (const host of hosting) {
    const hl  = host.toLowerCase();
    const idx = KNOWN_HOSTS.findIndex(h => hl.includes(h));
    vec[48 + (idx >= 0 ? idx : 9)] += 1;
  }

  return l2Normalise(vec);
}

/**
 * buildToolchainVector — encode malware/tool observations into 128-dim vector.
 *
 * @param {object} toolData - { malware_families: string[], packers: string[], yara_rules: string[] }
 * @returns {number[]} normalised 128-dim vector
 */
function buildToolchainVector(toolData) {
  const vec = new Array(TOOLCHAIN_DIM).fill(0);
  const { malware_families = [], packers = [], yara_rules = [] } = toolData;

  for (const family of malware_families) {
    const idx  = toolchainIndex(family);
    vec[idx]  += 1;
  }

  for (const packer of packers) {
    let h = 2166136261;
    for (let i = 0; i < packer.length; i++) { h ^= packer.charCodeAt(i); h = (h * 16777619) >>> 0; }
    const idx  = 64 + (h % 32); // packers in dims 64-95
    vec[idx]  += 1;
  }

  for (const rule of yara_rules) {
    let h = 2166136261;
    for (let i = 0; i < rule.length; i++) { h ^= rule.charCodeAt(i); h = (h * 16777619) >>> 0; }
    const idx  = 96 + (h % 32); // YARA rules in dims 96-127
    vec[idx]  += 1;
  }

  return l2Normalise(vec);
}

/**
 * buildDNA — construct a full 616-dim adversary DNA vector.
 *
 * @param {object} actorData - Aggregated intelligence for one threat actor
 * @param {string} actorData.actor_id
 * @param {Array}  actorData.ttps            - [{technique_id, count}]
 * @param {Array}  actorData.events          - [{timestamp}]
 * @param {object} actorData.infrastructure  - {asns, tlds, registrars, hosting}
 * @param {object} actorData.tools           - {malware_families, packers, yara_rules}
 * @returns {{
 *   actor_id: string,
 *   vector: number[],
 *   components: { ttp: number[], temporal: number[], infra: number[], toolchain: number[] },
 *   generated_at: string
 * }}
 */
function buildDNA(actorData) {
  const { actor_id, ttps = [], events = [], infrastructure = {}, tools = {} } = actorData;

  const ttpVec       = buildTTPVector(ttps);
  const temporalVec  = buildTemporalVector(events);
  const infraVec     = buildInfraVector(infrastructure);
  const toolchainVec = buildToolchainVector(tools);

  const vector = [...ttpVec, ...temporalVec, ...infraVec, ...toolchainVec];

  return {
    actor_id,
    vector,
    dimensions: DNA_DIMS,
    components: {
      ttp:       ttpVec,
      temporal:  temporalVec,
      infra:     infraVec,
      toolchain: toolchainVec,
    },
    generated_at: new Date().toISOString(),
  };
}

// ── Vector math ─────────────────────────────────────────────────────
function l2Normalise(vec) {
  const norm = Math.sqrt(vec.reduce((s, v) => s + v * v, 0)) || 1;
  return vec.map(v => v / norm);
}

function cosineSimilarity(a, b) {
  if (a.length !== b.length) return 0;
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na  += a[i] * a[i];
    nb  += b[i] * b[i];
  }
  return (na === 0 || nb === 0) ? 0 : dot / (Math.sqrt(na) * Math.sqrt(nb));
}

// ── Pinecone persistence ─────────────────────────────────────────────
const PINECONE_HOST     = process.env.PINECONE_HOST;
const PINECONE_API_KEY  = () => process.env.PINECONE_API_KEY;
const DNA_NAMESPACE     = 'adversary-dna';

async function pineconeUpsert(vectors) {
  if (!PINECONE_HOST || !PINECONE_API_KEY()) {
    console.warn('[AdversaryDNA] Pinecone not configured — skipping vector storage');
    return;
  }

  const payload = JSON.stringify({ vectors, namespace: DNA_NAMESPACE });
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: PINECONE_HOST, port: 443, path: '/vectors/upsert', method: 'POST',
      headers: { 'Api-Key': PINECONE_API_KEY(), 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch { resolve({}); } });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('Pinecone timeout')); });
    req.write(payload);
    req.end();
  });
}

async function pineconeQuery(vector, topK = 5) {
  if (!PINECONE_HOST || !PINECONE_API_KEY()) return [];

  const payload = JSON.stringify({ vector, topK, namespace: DNA_NAMESPACE, includeMetadata: true });
  return new Promise((resolve) => {
    const req = https.request({
      hostname: PINECONE_HOST, port: 443, path: '/query', method: 'POST',
      headers: { 'Api-Key': PINECONE_API_KEY(), 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString());
          resolve(body.matches || []);
        } catch { resolve([]); }
      });
    });
    req.on('error', () => resolve([]));
    req.setTimeout(15000, () => { req.destroy(); resolve([]); });
    req.write(payload);
    req.end();
  });
}

// ─────────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────────

/**
 * storeDNA — generate and persist a threat actor's DNA fingerprint.
 *
 * @param {object} actorData
 * @returns {Promise<object>}
 */
async function storeDNA(actorData) {
  if (!FEATURE_ENABLED) {
    return { skipped: true, reason: 'FEATURE_ADVERSARY_DNA not enabled' };
  }

  const dna = buildDNA(actorData);

  await pineconeUpsert([{
    id:       `dna-${actorData.actor_id}`,
    values:   dna.vector,
    metadata: {
      actor_id:     actorData.actor_id,
      actor_name:   actorData.actor_name || actorData.actor_id,
      generated_at: dna.generated_at,
      ttp_count:    actorData.ttps?.length || 0,
      event_count:  actorData.events?.length || 0,
    },
  }]);

  console.log(`[AdversaryDNA] Stored DNA for actor: ${actorData.actor_id} (${DNA_DIMS} dims)`);
  return { actor_id: actorData.actor_id, dimensions: DNA_DIMS, generated_at: dna.generated_at };
}

/**
 * attributeIncident — find the best-matching threat actor for a new incident's DNA.
 *
 * @param {object} incidentData - Same shape as actorData but for one incident
 * @param {object} [opts]
 * @param {number} [opts.topK=5]
 * @param {number} [opts.minSimilarity=0.65]
 * @returns {Promise<{ matches: Array, best_match: object|null }>}
 */
async function attributeIncident(incidentData, opts = {}) {
  const { topK = 5, minSimilarity = 0.65 } = opts;

  if (!FEATURE_ENABLED) return { matches: [], best_match: null, skipped: true };

  const dna     = buildDNA(incidentData);
  const results = await pineconeQuery(dna.vector, topK);

  const matches = results
    .filter(m => m.score >= minSimilarity)
    .map(m => ({
      actor_id:   m.metadata?.actor_id,
      actor_name: m.metadata?.actor_name,
      similarity: parseFloat(m.score.toFixed(4)),
      confidence: Math.round(m.score * 100),
    }));

  return {
    matches,
    best_match:        matches[0] || null,
    incident_dna_dims: DNA_DIMS,
    query_time:        new Date().toISOString(),
  };
}

/**
 * compareDNA — directly compare two actor DNA fingerprints.
 *
 * @param {object} actorDataA
 * @param {object} actorDataB
 * @returns {{ similarity: number, component_scores: object }}
 */
function compareDNA(actorDataA, actorDataB) {
  const dnaA = buildDNA(actorDataA);
  const dnaB = buildDNA(actorDataB);

  return {
    overall_similarity:   cosineSimilarity(dnaA.vector, dnaB.vector),
    component_scores: {
      ttp:       cosineSimilarity(dnaA.components.ttp,       dnaB.components.ttp),
      temporal:  cosineSimilarity(dnaA.components.temporal,  dnaB.components.temporal),
      infra:     cosineSimilarity(dnaA.components.infra,     dnaB.components.infra),
      toolchain: cosineSimilarity(dnaA.components.toolchain, dnaB.components.toolchain),
    },
  };
}

module.exports = {
  buildDNA,
  storeDNA,
  attributeIncident,
  compareDNA,
  buildTTPVector,
  buildTemporalVector,
  buildInfraVector,
  buildToolchainVector,
  cosineSimilarity,
  DNA_DIMS,
  TTP_DIM,
  TEMPORAL_DIM,
  INFRA_DIM,
  TOOLCHAIN_DIM,
};
