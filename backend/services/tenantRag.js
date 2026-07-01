/**
 * tenantRag.js
 * WS9: Tenant-Isolated RAG (Retrieval Augmented Generation)
 * - Pinecone: namespace = tenantId (mandatory server-side)
 * - Weaviate: class prefix = tenantId (mandatory server-side)
 * - Never trust client-provided namespace filters
 * - All vector operations scoped to tenant at the service layer
 */
'use strict';

const crypto = require('crypto');
const logger = require('../utils/logger');
const { BREAKERS, withRetry } = require('./circuitBreaker');

const _SRV = 'TenantRAG';

// ── Embedding helper ───────────────────────────────────────────────
async function embedText(text) {
  return await BREAKERS.openai.call(async () => {
    const res = await fetch('https://api.openai.com/v1/embeddings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify({ model: 'text-embedding-3-small', input: text }),
    });
    if (!res.ok) throw new Error(`OpenAI embeddings HTTP ${res.status}`);
    const json = await res.json();
    return json.data[0].embedding;
  });
}

// ── Pinecone Tenant-Scoped Operations ────────────────────────────
class PineconeTenantClient {
  constructor(tenantId) {
    if (!tenantId) throw new Error('TenantRAG: tenantId is required');
    this.tenantId  = tenantId;
    this.namespace = tenantId; // namespace IS the tenantId — not configurable from outside
    this.baseUrl   = `https://${process.env.PINECONE_INDEX_HOST}`;
    this.apiKey    = process.env.PINECONE_API_KEY;
  }

  async upsert(vectors) {
    return await BREAKERS.pinecone.call(async () => {
      // Inject tenant_id into all vector metadata
      const scoped = vectors.map(v => ({
        ...v,
        metadata: { ...v.metadata, tenant_id: this.tenantId },
      }));

      const res = await fetch(`${this.baseUrl}/vectors/upsert`, {
        method: 'POST',
        headers: { 'Api-Key': this.apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ vectors: scoped, namespace: this.namespace }),
      });
      if (!res.ok) throw new Error(`Pinecone upsert HTTP ${res.status}`);
      const data = await res.json();
      logger.info(_SRV, 'Pinecone upsert', { tenantId: this.tenantId, count: scoped.length });
      return data;
    });
  }

  async query(queryVector, topK = 10, filter = {}) {
    return await BREAKERS.pinecone.call(async () => {
      // Server-side: ALWAYS inject tenant_id filter, merge with any additional filters
      const scopedFilter = { ...filter, tenant_id: { '$eq': this.tenantId } };

      const res = await fetch(`${this.baseUrl}/query`, {
        method: 'POST',
        headers: { 'Api-Key': this.apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vector:          queryVector,
          topK,
          filter:          scopedFilter,
          namespace:       this.namespace,
          includeMetadata: true,
        }),
      });
      if (!res.ok) throw new Error(`Pinecone query HTTP ${res.status}`);
      const data = await res.json();

      // Defense-in-depth: strip any cross-tenant matches that slipped through
      const matches = (data.matches || []).filter(m =>
        m.metadata?.tenant_id === this.tenantId
      );
      if (matches.length !== (data.matches || []).length) {
        logger.error(_SRV, 'CROSS_TENANT_VECTOR_LEAK_PREVENTED', {
          tenantId: this.tenantId,
          expected: this.tenantId,
          filtered: (data.matches || []).length - matches.length,
        });
      }
      return { ...data, matches };
    });
  }

  async delete(ids) {
    return await BREAKERS.pinecone.call(async () => {
      const res = await fetch(`${this.baseUrl}/vectors/delete`, {
        method: 'POST',
        headers: { 'Api-Key': this.apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids, namespace: this.namespace }),
      });
      if (!res.ok) throw new Error(`Pinecone delete HTTP ${res.status}`);
      return res.json();
    });
  }

  async fetch(ids) {
    return await BREAKERS.pinecone.call(async () => {
      const res = await fetch(`${this.baseUrl}/vectors/fetch?ids=${ids.join('&ids=')}&namespace=${this.namespace}`, {
        headers: { 'Api-Key': this.apiKey },
      });
      if (!res.ok) throw new Error(`Pinecone fetch HTTP ${res.status}`);
      const data = await res.json();
      // Validate tenant ownership of fetched vectors
      const valid = {};
      for (const [id, vec] of Object.entries(data.vectors || {})) {
        if (vec.metadata?.tenant_id === this.tenantId) valid[id] = vec;
      }
      return { vectors: valid };
    });
  }
}

// ── Weaviate Tenant-Scoped Operations ─────────────────────────────
class WeaviateTenantClient {
  constructor(tenantId) {
    if (!tenantId) throw new Error('TenantRAG: tenantId is required');
    this.tenantId = tenantId;
    // Each tenant gets its own class prefix for complete isolation
    this.classPrefix = tenantId.replace(/[^a-zA-Z0-9]/g, '_');
    this.baseUrl     = process.env.WEAVIATE_URL || 'http://localhost:8080';
    this.apiKey      = process.env.WEAVIATE_API_KEY;
  }

  _headers() {
    const h = { 'Content-Type': 'application/json' };
    if (this.apiKey) h['Authorization'] = `Bearer ${this.apiKey}`;
    return h;
  }

  _className(base) {
    return `${this.classPrefix}_${base}`;
  }

  async insertObject(className, properties, vector) {
    return await BREAKERS.weaviate.call(async () => {
      const obj = {
        class:      this._className(className),
        properties: { ...properties, tenant_id: this.tenantId },
        ...(vector && { vector }),
      };
      const res = await fetch(`${this.baseUrl}/v1/objects`, {
        method: 'POST', headers: this._headers(),
        body: JSON.stringify(obj),
      });
      if (!res.ok) throw new Error(`Weaviate insert HTTP ${res.status}`);
      return res.json();
    });
  }

  async nearTextSearch(className, query, limit = 10, certainty = 0.7) {
    return await BREAKERS.weaviate.call(async () => {
      const gql = `{
        Get {
          ${this._className(className)}(
            nearText: { concepts: ["${query}"], certainty: ${certainty} }
            limit: ${limit}
            where: { path: ["tenant_id"], operator: Equal, valueText: "${this.tenantId}" }
          ) { _additional { id certainty } }
        }
      }`;
      const res = await fetch(`${this.baseUrl}/v1/graphql`, {
        method: 'POST', headers: this._headers(),
        body: JSON.stringify({ query: gql }),
      });
      if (!res.ok) throw new Error(`Weaviate search HTTP ${res.status}`);
      const data = await res.json();
      return data.data?.Get?.[this._className(className)] || [];
    });
  }
}

// ── High-Level RAG Service ────────────────────────────────────────
class TenantRAGService {
  constructor(tenantId) {
    this.tenantId = tenantId;
    this.pinecone = new PineconeTenantClient(tenantId);
    this.weaviate = new WeaviateTenantClient(tenantId);
  }

  async ingestDocument(doc) {
    const { id, content, metadata = {}, chunkSize = 1000, overlap = 100 } = doc;
    if (!id || !content) throw new Error('Document requires id and content');

    // Chunk the document
    const chunks = chunkText(content, chunkSize, overlap);
    const vectors = [];

    for (let i = 0; i < chunks.length; i++) {
      const chunkId = `${id}_chunk_${i}`;
      const embedding = await withRetry(() => embedText(chunks[i]));
      vectors.push({
        id:       chunkId,
        values:   embedding,
        metadata: {
          ...metadata,
          tenant_id:  this.tenantId,
          doc_id:     id,
          chunk_idx:  i,
          chunk_text: chunks[i].slice(0, 200),
        },
      });
    }

    // Upsert all chunks in batch
    await this.pinecone.upsert(vectors);
    logger.info(_SRV, 'Document ingested', { tenantId: this.tenantId, docId: id, chunks: vectors.length });
    return { doc_id: id, chunks_indexed: vectors.length };
  }

  async retrieve(query, opts = {}) {
    const { topK = 10, filter = {}, minScore = 0.7 } = opts;
    const queryVector = await withRetry(() => embedText(query));
    const results = await this.pinecone.query(queryVector, topK, filter);
    return (results.matches || []).filter(m => m.score >= minScore);
  }

  async deleteDocument(docId) {
    // Fetch chunk IDs for this document then delete
    const results = await this.pinecone.query(
      new Array(1536).fill(0), 100,
      { doc_id: { '$eq': docId } }
    );
    const ids = results.matches.map(m => m.id);
    if (ids.length > 0) await this.pinecone.delete(ids);
    logger.info(_SRV, 'Document deleted', { tenantId: this.tenantId, docId, chunksRemoved: ids.length });
    return { deleted: ids.length };
  }
}

function chunkText(text, size, overlap) {
  const chunks = [];
  let start = 0;
  while (start < text.length) {
    chunks.push(text.slice(start, start + size));
    start += size - overlap;
  }
  return chunks;
}

function fromRequest(req) {
  const tenantId = req.tenantId || req.user?.tenant_id;
  if (!tenantId) throw new Error('TenantRAG: request missing tenantId');
  return new TenantRAGService(tenantId);
}

module.exports = {
  TenantRAGService,
  PineconeTenantClient,
  WeaviateTenantClient,
  fromRequest,
  embedText,
};
