/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — RAG Pipeline (Phase 3)
 *  backend/services/rag/rag-pipeline.js
 *
 *  Retrieval-Augmented Generation pipeline:
 *  • Ingests threat reports, MITRE ATT&CK, CVEs, playbooks
 *  • Vectorises with text-embedding-3-large
 *  • Stores in Pinecone (primary) / Weaviate (fallback)
 *  • Enables semantic search across all security knowledge
 *
 *  Audit finding: No RAG pipeline for context-aware investigation
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const https   = require('https');
const crypto  = require('crypto');

// ── Configuration ─────────────────────────────────────────────────
const OPENAI_API_KEY    = () => process.env.OPENAI_API_KEY || process.env.RAKAY_OPENAI_KEY;
const PINECONE_API_KEY  = () => process.env.PINECONE_API_KEY;
const PINECONE_INDEX    = process.env.PINECONE_INDEX   || 'wadjet-eye';
const PINECONE_HOST     = process.env.PINECONE_HOST;   // e.g. wadjet-eye-xxxxx.svc.us-east1-gcp.pinecone.io
const WEAVIATE_URL      = process.env.WEAVIATE_URL     || 'http://weaviate:8080';
const EMBED_MODEL       = process.env.EMBED_MODEL      || 'text-embedding-3-large';
const EMBED_DIMENSIONS  = parseInt(process.env.EMBED_DIMENSIONS || '1536', 10);
const CHUNK_SIZE        = parseInt(process.env.RAG_CHUNK_SIZE   || '800',  10);
const CHUNK_OVERLAP     = parseInt(process.env.RAG_CHUNK_OVERLAP|| '100',  10);

// ── Namespaces (logical partitions in the vector store) ───────────
const NAMESPACES = {
  MITRE:          'mitre-attack',
  CVE:            'cve-database',
  THREAT_REPORTS: 'threat-reports',
  INCIDENTS:      'past-incidents',
  IOCS:           'ioc-context',
  PLAYBOOKS:      'playbooks',
  ACTORS:         'threat-actors',
};

// ── Embeddings ────────────────────────────────────────────────────

/**
 * embed — generate embeddings via OpenAI text-embedding-3-large
 * Supports batch embedding (up to 2048 texts per call).
 * Falls back to a deterministic hash-based embedding for offline mode.
 *
 * @param {string|string[]} texts - Text(s) to embed
 * @returns {Promise<number[][]>} Array of embedding vectors
 */
async function embed(texts) {
  const textArr = Array.isArray(texts) ? texts : [texts];
  const key     = OPENAI_API_KEY();

  if (!key) {
    console.warn('[RAG] No OpenAI key — using deterministic hash embeddings (offline mode)');
    return textArr.map(t => hashEmbed(t, EMBED_DIMENSIONS));
  }

  // Batch in groups of 100 to avoid token limits
  const results = [];
  for (let i = 0; i < textArr.length; i += 100) {
    const batch = textArr.slice(i, i + 100);
    const resp  = await openaiRequest('/v1/embeddings', 'POST', {
      model:      EMBED_MODEL,
      input:      batch,
      dimensions: EMBED_DIMENSIONS,
    });
    results.push(...resp.data.map(d => d.embedding));
  }
  return results;
}

/** Single text embedding convenience wrapper */
async function embedOne(text) {
  const [vec] = await embed([text]);
  return vec;
}

/**
 * hashEmbed — deterministic fallback embedding (no API key needed)
 * NOT semantically meaningful — only for offline/test mode.
 */
function hashEmbed(text, dims) {
  const hash = crypto.createHash('sha512').update(text).digest();
  const vec  = [];
  for (let i = 0; i < dims; i++) {
    vec.push((hash[i % hash.length] - 128) / 128.0);
  }
  // L2-normalize
  const norm = Math.sqrt(vec.reduce((s, v) => s + v * v, 0)) || 1;
  return vec.map(v => v / norm);
}

// ── Text chunking ─────────────────────────────────────────────────

/**
 * chunkText — split document into overlapping chunks for embedding
 * @param {string} text - Full document text
 * @param {object} metadata - Document metadata (title, source, type, etc.)
 * @returns {Array<{text: string, metadata: object, chunk_idx: number}>}
 */
function chunkText(text, metadata = {}) {
  const words  = text.split(/\s+/);
  const chunks = [];
  let   idx    = 0;

  for (let start = 0; start < words.length; start += CHUNK_SIZE - CHUNK_OVERLAP) {
    const end       = Math.min(start + CHUNK_SIZE, words.length);
    const chunkText = words.slice(start, end).join(' ');

    if (chunkText.trim().length < 50) continue;   // Skip tiny chunks

    chunks.push({
      text:      chunkText,
      chunk_idx: idx++,
      metadata:  {
        ...metadata,
        chunk_idx: idx - 1,
        chunk_start: start,
        chunk_end:   end,
        char_count:  chunkText.length,
      },
    });

    if (end >= words.length) break;
  }

  return chunks;
}

// ── Vector store abstraction ──────────────────────────────────────

/**
 * upsertVectors — store embeddings in Pinecone (or Weaviate fallback)
 * @param {Array<{id, values, metadata}>} vectors
 * @param {string} namespace - NAMESPACES constant
 */
async function upsertVectors(vectors, namespace = NAMESPACES.THREAT_REPORTS) {
  if (PINECONE_API_KEY() && PINECONE_HOST) {
    return upsertPinecone(vectors, namespace);
  }
  return upsertWeaviate(vectors, namespace);
}

/**
 * queryVectors — semantic search across the knowledge base
 * @param {number[]} queryVector - Query embedding
 * @param {object} opts - { namespace, topK, filter, minScore }
 * @returns {Promise<Array<{id, score, metadata, text}>>}
 */
async function queryVectors(queryVector, opts = {}) {
  const { namespace = null, topK = 5, filter = {}, minScore = 0.7 } = opts;

  let results;
  if (PINECONE_API_KEY() && PINECONE_HOST) {
    results = await queryPinecone(queryVector, { namespace, topK: topK * 2, filter });
  } else {
    results = await queryWeaviate(queryVector, { namespace, topK: topK * 2 });
  }

  return results
    .filter(r => r.score >= minScore)
    .slice(0, topK);
}

// ── Pinecone implementation ───────────────────────────────────────

async function upsertPinecone(vectors, namespace) {
  const batchSize = 100;
  for (let i = 0; i < vectors.length; i += batchSize) {
    const batch = vectors.slice(i, i + batchSize);
    await pineconeRequest('POST', `/vectors/upsert`, {
      vectors: batch.map(v => ({
        id:       v.id,
        values:   v.values,
        metadata: { ...v.metadata, namespace },
      })),
      namespace,
    });
  }
}

async function queryPinecone(vector, opts) {
  const resp = await pineconeRequest('POST', '/query', {
    vector:          vector,
    topK:            opts.topK || 10,
    namespace:       opts.namespace,
    filter:          opts.filter || {},
    includeMetadata: true,
    includeValues:   false,
  });
  return (resp.matches || []).map(m => ({
    id:       m.id,
    score:    m.score,
    metadata: m.metadata,
    text:     m.metadata?.text || '',
  }));
}

async function pineconeRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = https.request({
      hostname: PINECONE_HOST,
      port:     443,
      path,
      method,
      headers: {
        'Api-Key':        PINECONE_API_KEY(),
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
        catch { resolve({}); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('Pinecone timeout')); });
    req.write(payload);
    req.end();
  });
}

// ── Weaviate fallback ─────────────────────────────────────────────

async function upsertWeaviate(vectors, namespace) {
  const className = `ThreatIntel_${namespace.replace(/[^a-zA-Z0-9]/g, '_')}`;
  for (const vec of vectors) {
    try {
      await weaviateRequest('POST', `/v1/objects`, {
        class:      className,
        id:         vec.id,
        properties: { ...vec.metadata, text: vec.metadata?.text || '' },
        vector:     vec.values,
      });
    } catch (err) {
      if (!err.message.includes('already exists')) console.warn('[Weaviate] Upsert warning:', err.message);
    }
  }
}

async function queryWeaviate(vector, opts) {
  const className = `ThreatIntel_${(opts.namespace || 'default').replace(/[^a-zA-Z0-9]/g, '_')}`;
  const gql = `{
    Get { ${className}(nearVector: { vector: [${vector.slice(0,10).join(',')}] }, limit: ${opts.topK || 10}) {
      _additional { id certainty }
      text source title
    }}
  }`;
  try {
    const resp = await weaviateRequest('POST', '/v1/graphql', { query: gql });
    const objs = resp.data?.Get?.[className] || [];
    return objs.map(o => ({ id: o._additional?.id, score: o._additional?.certainty || 0, metadata: o, text: o.text || '' }));
  } catch {
    return [];
  }
}

async function weaviateRequest(method, path, body) {
  const { http } = require('http');
  const url      = new URL(WEAVIATE_URL + path);
  const payload  = body ? JSON.stringify(body) : null;

  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : require('http');
    const req = transport.request({
      hostname: url.hostname,
      port:     url.port || (url.protocol === 'https:' ? 443 : 80),
      path:     url.pathname,
      method,
      headers: { 'Content-Type': 'application/json', ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}) },
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch { resolve({}); } });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('Weaviate timeout')); });
    if (payload) req.write(payload);
    req.end();
  });
}

// ── OpenAI HTTP helper ────────────────────────────────────────────
async function openaiRequest(path, method, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = https.request({
      hostname: 'api.openai.com',
      port:     443,
      path,
      method,
      headers: {
        'Authorization': `Bearer ${OPENAI_API_KEY()}`,
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString();
        if (res.statusCode >= 400) return reject(new Error(`OpenAI ${res.statusCode}: ${body.slice(0,200)}`));
        try { resolve(JSON.parse(body)); } catch { reject(new Error('OpenAI invalid JSON')); }
      });
    });
    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('OpenAI timeout')); });
    req.write(payload);
    req.end();
  });
}

// ── Document ingestion ────────────────────────────────────────────

/**
 * ingestDocument — chunk, embed, and store a security document
 * @param {string} text - Document text content
 * @param {object} metadata - { title, source, type, url, date, ... }
 * @param {string} namespace - Which knowledge base to store in
 */
async function ingestDocument(text, metadata = {}, namespace = NAMESPACES.THREAT_REPORTS) {
  const chunks    = chunkText(text, metadata);
  const docId     = metadata.id || crypto.randomUUID();

  console.log(`[RAG] Ingesting document '${metadata.title || docId}' → ${chunks.length} chunks → namespace: ${namespace}`);

  // Batch embed all chunks
  const chunkTexts = chunks.map(c => c.text);
  const embeddings = await embed(chunkTexts);

  // Build vectors
  const vectors = chunks.map((chunk, i) => ({
    id:     `${docId}-${chunk.chunk_idx}`,
    values: embeddings[i],
    metadata: {
      ...chunk.metadata,
      text:      chunk.text,
      doc_id:    docId,
      namespace,
    },
  }));

  await upsertVectors(vectors, namespace);

  return {
    doc_id:      docId,
    chunks:      chunks.length,
    namespace,
    ingested_at: new Date().toISOString(),
  };
}

/**
 * ingestMitreAttack — bulk ingest MITRE ATT&CK technique descriptions
 * @param {Array<{id, name, description, tactic, url}>} techniques
 */
async function ingestMitreAttack(techniques) {
  let total = 0;
  for (const tech of techniques) {
    const text = `MITRE ATT&CK Technique: ${tech.id} — ${tech.name}\nTactic: ${tech.tactic}\n\n${tech.description}`;
    await ingestDocument(text, {
      id:     `mitre-${tech.id}`,
      title:  `${tech.id}: ${tech.name}`,
      source: 'mitre-attack',
      type:   'technique',
      url:    `https://attack.mitre.org/techniques/${tech.id}/`,
      mitre_id: tech.id,
      tactic: tech.tactic,
    }, NAMESPACES.MITRE);
    total++;
  }
  return { ingested: total };
}

/**
 * ingestCveDescriptions — ingest NVD CVE descriptions for context
 */
async function ingestCveDescriptions(cves) {
  let total = 0;
  for (const cve of cves) {
    const text = `CVE: ${cve.id}\nCVSS Score: ${cve.cvss || 'N/A'}\nSummary: ${cve.description}\nAffected: ${cve.affected?.join(', ') || 'Unknown'}`;
    await ingestDocument(text, {
      id:       `cve-${cve.id}`,
      title:    cve.id,
      source:   'nvd',
      type:     'cve',
      cve_id:   cve.id,
      cvss:     cve.cvss,
      published: cve.published,
    }, NAMESPACES.CVE);
    total++;
  }
  return { ingested: total };
}

// ── Semantic search ───────────────────────────────────────────────

/**
 * search — semantic search across knowledge bases
 * @param {string} query - Natural language query
 * @param {object} opts - { namespaces, topK, minScore, filter }
 * @returns {Promise<{ results: object[], sources: string[] }>}
 */
async function search(query, opts = {}) {
  const { namespaces = null, topK = 5, minScore = 0.65, filter = {} } = opts;
  const queryVec = await embedOne(query);

  let allResults = [];

  const namespacesToSearch = namespaces || Object.values(NAMESPACES);
  for (const ns of (Array.isArray(namespacesToSearch) ? namespacesToSearch : [namespacesToSearch])) {
    const results = await queryVectors(queryVec, { namespace: ns, topK, filter, minScore });
    allResults.push(...results.map(r => ({ ...r, namespace: ns })));
  }

  // Deduplicate and sort by score
  const seen = new Set();
  allResults = allResults
    .filter(r => { if (seen.has(r.id)) return false; seen.add(r.id); return true; })
    .sort((a, b) => b.score - a.score)
    .slice(0, topK);

  const sources = [...new Set(allResults.map(r => r.metadata?.source || r.namespace).filter(Boolean))];

  return {
    query,
    results:   allResults,
    sources,
    total:     allResults.length,
    namespace: namespacesToSearch,
  };
}

/**
 * buildContext — retrieve relevant context for an alert/IOC investigation
 * Returns structured context blocks for LLM injection.
 *
 * @param {object} alert - Alert or incident object
 * @returns {Promise<{context_blocks: string[], sources: string[]}>}
 */
async function buildContext(alert) {
  const queries = [];

  // Build search queries from alert data
  if (alert.mitre_tactic)  queries.push({ q: `${alert.mitre_tactic} attack technique defense evasion`, ns: NAMESPACES.MITRE });
  if (alert.mitre_tech)    queries.push({ q: `${alert.mitre_tech} ${alert.title}`, ns: NAMESPACES.MITRE });
  if (alert.title)         queries.push({ q: alert.title, ns: NAMESPACES.THREAT_REPORTS });
  if (alert.iocs?.length)  queries.push({ q: alert.iocs.slice(0,3).join(' '), ns: NAMESPACES.IOCS });

  const allResults = [];
  await Promise.allSettled(
    queries.map(async ({ q, ns }) => {
      const { results } = await search(q, { namespaces: [ns], topK: 3, minScore: 0.6 });
      allResults.push(...results);
    })
  );

  // Deduplicate and build context blocks
  const seen     = new Set();
  const blocks   = [];
  const sources  = [];

  for (const r of allResults.sort((a, b) => b.score - a.score).slice(0, 8)) {
    if (seen.has(r.id)) continue;
    seen.add(r.id);
    blocks.push(`[${r.metadata?.title || r.metadata?.source || 'Reference'}]\n${r.text}`);
    if (r.metadata?.source) sources.push(r.metadata.source);
  }

  return { context_blocks: blocks, sources: [...new Set(sources)] };
}

module.exports = {
  embed,
  embedOne,
  chunkText,
  ingestDocument,
  ingestMitreAttack,
  ingestCveDescriptions,
  upsertVectors,
  queryVectors,
  search,
  buildContext,
  NAMESPACES,
  hashEmbed,
};
