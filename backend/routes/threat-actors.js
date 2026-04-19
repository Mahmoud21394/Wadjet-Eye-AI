/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Threat Actors Intelligence API v5.3
 *  backend/routes/threat-actors.js
 *
 *  Endpoints:
 *   GET    /api/threat-actors              List with search/filter/pagination
 *   GET    /api/threat-actors/stats        KPI counts (total, nation-state, ransomware, active)
 *   GET    /api/threat-actors/countries    Unique country list for filter dropdown
 *   GET    /api/threat-actors/:id          Full actor profile
 *   GET    /api/threat-actors/:id/iocs     IOCs attributed to this actor
 *   GET    /api/threat-actors/:id/campaigns Campaigns attributed to this actor
 *   GET    /api/threat-actors/:id/timeline  Event timeline for this actor
 *   POST   /api/threat-actors              Create actor manually
 *   PATCH  /api/threat-actors/:id          Update actor
 *   DELETE /api/threat-actors/:id          Delete actor
 *   POST   /api/threat-actors/ingest/otx   Pull actors from AlienVault OTX
 *   POST   /api/threat-actors/ingest/mitre  Pull actors from MITRE ATT&CK (STIX)
 *   POST   /api/threat-actors/ingest/threatfox  Pull actor tags from ThreatFox
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const router  = require('express').Router();
const axios   = require('axios');
const { createClient } = require('@supabase/supabase-js');
const { verifyToken, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

// Use service_role for writes (bypass RLS)
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// Use anon/user client for reads (respects RLS)
const { supabase } = require('../config/supabase');

const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || '00000000-0000-0000-0000-000000000001';

// ── Helpers ─────────────────────────────────────────────────────
function paginate(req) {
  const page  = Math.max(1, parseInt(req.query.page)  || 1);
  const limit = Math.min(200, parseInt(req.query.limit) || 24);
  return { page, limit, from: (page - 1) * limit, to: (page - 1) * limit + limit - 1 };
}

function tenantId(req) {
  return req.user?.tenant_id || req.tenantId || DEFAULT_TENANT;
}

// ── GET /api/threat-actors ───────────────────────────────────────
router.get('/', verifyToken, asyncHandler(async (req, res) => {
  const { page, limit, from, to } = paginate(req);
  const tid = tenantId(req);

  let q = supabase
    .from('threat_actors')
    .select('*', { count: 'exact' })
    .or(`tenant_id.eq.${tid},tenant_id.is.null`)
    .order('updated_at', { ascending: false })
    .range(from, to);

  if (req.query.search) {
    // Search name, aliases array, description
    q = q.or(`name.ilike.%${req.query.search}%,description.ilike.%${req.query.search}%`);
  }
  if (req.query.motivation)     q = q.eq('motivation', req.query.motivation);
  if (req.query.sophistication) q = q.eq('sophistication', req.query.sophistication);
  if (req.query.origin_country) q = q.eq('origin_country', req.query.origin_country);

  // Active only — last_seen within 30 days
  if (req.query.active_only === 'true') {
    const d30 = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString();
    q = q.gte('last_seen', d30);
  }

  const { data, error, count } = await q;
  if (error) return res.status(500).json({ error: error.message });

  res.json({
    data:  data || [],
    total: count || 0,
    page,
    limit,
    has_more: (from + limit) < (count || 0),
  });
}));

// ── GET /api/threat-actors/stats ─────────────────────────────────
router.get('/stats', verifyToken, asyncHandler(async (req, res) => {
  const tid = tenantId(req);

  const [total, nationState, ransomware, activeResult] = await Promise.all([
    supabase.from('threat_actors').select('*', { count: 'exact', head: true })
      .or(`tenant_id.eq.${tid},tenant_id.is.null`),
    supabase.from('threat_actors').select('*', { count: 'exact', head: true })
      .or(`tenant_id.eq.${tid},tenant_id.is.null`)
      .eq('sophistication', 'nation-state'),
    supabase.from('threat_actors').select('*', { count: 'exact', head: true })
      .or(`tenant_id.eq.${tid},tenant_id.is.null`)
      .ilike('motivation', '%ransomware%'),
    supabase.from('threat_actors').select('*', { count: 'exact', head: true })
      .or(`tenant_id.eq.${tid},tenant_id.is.null`)
      .gte('last_seen', new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString()),
  ]);

  res.json({
    total:       total.count       || 0,
    nation_state: nationState.count || 0,
    ransomware:  ransomware.count  || 0,
    active_30d:  activeResult.count || 0,
  });
}));

// ── GET /api/threat-actors/countries ─────────────────────────────
router.get('/countries', verifyToken, asyncHandler(async (req, res) => {
  const tid = tenantId(req);

  const { data, error } = await supabase
    .from('threat_actors')
    .select('origin_country')
    .or(`tenant_id.eq.${tid},tenant_id.is.null`)
    .not('origin_country', 'is', null)
    .limit(500);

  if (error) return res.status(500).json({ error: error.message });

  const countries = [...new Set((data || []).map(r => r.origin_country).filter(Boolean))].sort();
  res.json({ countries });
}));

// ── GET /api/threat-actors/:id ───────────────────────────────────
router.get('/:id', verifyToken, asyncHandler(async (req, res) => {
  const tid = tenantId(req);

  const { data, error } = await supabase
    .from('threat_actors')
    .select('*')
    .eq('id', req.params.id)
    .or(`tenant_id.eq.${tid},tenant_id.is.null`)
    .single();

  if (error || !data) return res.status(404).json({ error: 'Threat actor not found' });
  res.json(data);
}));

// ── GET /api/threat-actors/:id/iocs ──────────────────────────────
router.get('/:id/iocs', verifyToken, asyncHandler(async (req, res) => {
  const tid  = tenantId(req);
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, parseInt(req.query.limit) || 25);

  // First get actor name
  const { data: actor } = await supabase
    .from('threat_actors')
    .select('name')
    .eq('id', req.params.id)
    .single();

  if (!actor) return res.status(404).json({ error: 'Actor not found' });

  const { data, error, count } = await supabase
    .from('iocs')
    .select('id,value,type,risk_score,reputation,confidence,last_seen,first_seen,malware_family,tags,source,country', { count: 'exact' })
    .eq('tenant_id', tid)
    .ilike('threat_actor', `%${actor.name}%`)
    .order('risk_score', { ascending: false })
    .range((page - 1) * limit, (page - 1) * limit + limit - 1);

  if (error) return res.status(500).json({ error: error.message });

  res.json({ data: data || [], total: count || 0, page, limit, actor_name: actor.name });
}));

// ── GET /api/threat-actors/:id/campaigns ─────────────────────────
router.get('/:id/campaigns', verifyToken, asyncHandler(async (req, res) => {
  const tid = tenantId(req);

  const { data, error } = await supabase
    .from('campaigns')
    .select('id,name,status,start_date,end_date,target_sectors,target_countries,confidence,updated_at,description')
    .or(`tenant_id.eq.${tid},tenant_id.is.null`)
    .eq('actor_id', req.params.id)
    .order('updated_at', { ascending: false })
    .limit(50);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data || [], total: (data || []).length });
}));

// ── GET /api/threat-actors/:id/timeline ──────────────────────────
router.get('/:id/timeline', verifyToken, asyncHandler(async (req, res) => {
  const tid = tenantId(req);

  // Get actor for name
  const { data: actor } = await supabase
    .from('threat_actors')
    .select('name')
    .eq('id', req.params.id)
    .single();

  if (!actor) return res.status(404).json({ error: 'Actor not found' });

  // Fetch timeline events mentioning this actor
  const { data, error } = await supabase
    .from('detection_timeline')
    .select('*')
    .eq('tenant_id', tid)
    .ilike('actor', `%${actor.name}%`)
    .order('detected_at', { ascending: false })
    .limit(50);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ data: data || [], actor_name: actor.name });
}));

// ── POST /api/threat-actors ──────────────────────────────────────
router.post('/', verifyToken, requireRole(['ADMIN','ANALYST','SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const {
    name, description, motivation, sophistication, origin_country,
    active_since, last_seen, target_sectors, target_countries, ttps,
    tools, malware, aliases, tags, confidence, external_id, source
  } = req.body;

  if (!name) return res.status(400).json({ error: 'name is required' });

  const { data, error } = await supabaseAdmin
    .from('threat_actors')
    .insert({
      tenant_id:       tenantId(req),
      name, description, motivation, sophistication,
      origin_country,  active_since, last_seen,
      target_sectors:  target_sectors  || [],
      target_countries: target_countries || [],
      ttps:    ttps    || [],
      tools:   tools   || [],
      malware: malware || [],
      aliases: aliases || [],
      tags:    tags    || [],
      confidence: confidence || 50,
      external_id,
      source: source || 'manual',
    })
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
}));

// ── PATCH /api/threat-actors/:id ─────────────────────────────────
router.patch('/:id', verifyToken, requireRole(['ADMIN','ANALYST','SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const allowed = [
    'name','description','motivation','sophistication','origin_country',
    'active_since','last_seen','target_sectors','target_countries','ttps',
    'tools','malware','aliases','tags','confidence','external_id'
  ];
  const updates = {};
  for (const k of allowed) {
    if (req.body[k] !== undefined) updates[k] = req.body[k];
  }
  updates.updated_at = new Date().toISOString();

  const { data, error } = await supabaseAdmin
    .from('threat_actors')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
}));

// ── DELETE /api/threat-actors/:id ────────────────────────────────
router.delete('/:id', verifyToken, requireRole(['ADMIN','SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const { error } = await supabaseAdmin
    .from('threat_actors')
    .delete()
    .eq('id', req.params.id);

  if (error) return res.status(500).json({ error: error.message });
  res.status(204).send();
}));

// ══════════════════════════════════════════════════════════════════
//  INGESTION ENDPOINTS
// ══════════════════════════════════════════════════════════════════

/**
 * POST /api/threat-actors/ingest/otx
 * Pull threat actor groups and their pulses from AlienVault OTX.
 * Requires OTX_API_KEY in .env
 */
router.post('/ingest/otx', verifyToken, requireRole(['ADMIN','SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const key = process.env.OTX_API_KEY;
  if (!key) {
    return res.status(502).json({
      success: false,
      error:   'OTX_API_KEY not set in backend/.env',
      auth_error: true,
    });
  }

  const tid   = tenantId(req);
  const t0    = Date.now();
  const actors = [];

  try {
    // 1. Pull recent pulses tagged with threat actor names
    const pulsesRes = await axios.get('https://otx.alienvault.com/api/v1/pulses/subscribed', {
      headers: { 'X-OTX-API-KEY': key, 'User-Agent': 'wadjet-eye-ai/5.3' },
      params:  { limit: 100, modified_since: new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString() },
      timeout: 30000,
      validateStatus: null,
    });

    if (pulsesRes.status !== 200) {
      return res.status(502).json({
        success:    false,
        error:      `OTX returned HTTP ${pulsesRes.status}`,
        auth_error: pulsesRes.status === 401,
      });
    }

    const pulses = pulsesRes.data?.results || [];

    // Build a map of actor name → pulse data
    const actorMap = new Map();

    for (const pulse of pulses) {
      // Tags often contain actor names / groups
      const actorTags = (pulse.tags || []).filter(t =>
        t && t.length > 2 && !['malware','ransomware','phishing','apt','cybercrime'].includes(t.toLowerCase())
      );

      // Also try adversary field
      const adversary = pulse.adversary || null;
      const actorName = adversary || actorTags[0] || null;

      if (!actorName) continue;

      const key2 = actorName.toLowerCase();
      if (!actorMap.has(key2)) {
        actorMap.set(key2, {
          name:         actorName,
          description:  pulse.description || `Threat actor identified from OTX pulse: ${pulse.name}`,
          motivation:   _guessMotivation(pulse.tags),
          sophistication: _guessSophistication(pulse.tags, pulse.tlp),
          origin_country: _guessCountry(pulse.tags, adversary),
          last_seen:    pulse.modified || pulse.created,
          active_since: pulse.created,
          tags:         (pulse.tags || []).slice(0, 10),
          malware:      [],
          aliases:      adversary ? [adversary] : [],
          confidence:   pulse.pulse_source === 'user' ? 60 : 75,
          source:       'otx',
          external_id:  `otx:${pulse.id}`,
          pulses:       0,
          ioc_count:    0,
        });
      }
      const entry = actorMap.get(key2);
      entry.pulses++;
      entry.ioc_count += (pulse.indicator_count || 0);
    }

    // Upsert each actor
    let inserted = 0, updated = 0;
    for (const [, actor] of actorMap) {
      const row = {
        tenant_id:        tid,
        name:             actor.name,
        description:      actor.description,
        motivation:       actor.motivation,
        sophistication:   actor.sophistication,
        origin_country:   actor.origin_country,
        last_seen:        actor.last_seen,
        active_since:     actor.active_since,
        tags:             actor.tags,
        malware:          actor.malware,
        aliases:          actor.aliases,
        confidence:       actor.confidence,
        source:           'otx',
        external_id:      actor.external_id,
        ttps:             [],
        tools:            [],
        target_sectors:   [],
        target_countries: [],
        updated_at:       new Date().toISOString(),
      };

      const { error: uErr } = await supabaseAdmin
        .from('threat_actors')
        .upsert(row, { onConflict: 'tenant_id,name', ignoreDuplicates: false });

      if (!uErr) {
        actors.push(actor.name);
        inserted++;
      }
    }

    res.json({
      success:     true,
      actors_ingested: inserted,
      actors:      actors.slice(0, 20),
      pulses_scanned: pulses.length,
      duration_ms: Date.now() - t0,
      source:      'otx',
    });

  } catch (err) {
    console.error('[Threat-Actors][OTX Ingest] Error:', err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
}));

/**
 * POST /api/threat-actors/ingest/mitre
 * Pull threat actor groups from MITRE ATT&CK STIX data (public, no auth required).
 */
router.post('/ingest/mitre', verifyToken, requireRole(['ADMIN','SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const tid = tenantId(req);
  const t0  = Date.now();

  try {
    // MITRE ATT&CK enterprise groups (public STIX endpoint)
    const url  = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
    const resp = await axios.get(url, {
      timeout: 45000,
      headers: { 'User-Agent': 'wadjet-eye-ai/5.3' },
      validateStatus: null,
    });

    if (resp.status !== 200) {
      return res.status(502).json({ success: false, error: `MITRE CTI returned HTTP ${resp.status}` });
    }

    const stix    = resp.data;
    const objects = stix.objects || [];

    // Filter only group objects
    const groups = objects.filter(o => o.type === 'intrusion-set');

    // Build country/TTP lookup from relationships
    const relationships = objects.filter(o => o.type === 'relationship');
    const techniques    = Object.fromEntries(
      objects.filter(o => o.type === 'attack-pattern').map(o => [o.id, o])
    );

    let inserted = 0;
    const processed = [];

    for (const group of groups.slice(0, 200)) {
      // Get TTPs for this group
      const groupRels = relationships.filter(r =>
        r.source_ref === group.id && r.relationship_type === 'uses'
      );
      const ttps = groupRels
        .map(r => techniques[r.target_ref])
        .filter(Boolean)
        .map(t => t.external_references?.[0]?.external_id || t.name)
        .filter(Boolean)
        .slice(0, 20);

      // Get external refs
      const extRefs = group.external_references || [];
      const mitreRef = extRefs.find(r => r.source_name === 'mitre-attack');
      const groupId  = mitreRef?.external_id || group.id;

      // Extract country from x_mitre_contributors or name
      const country = _extractCountryFromGroup(group);

      const row = {
        tenant_id:        tid,
        name:             group.name,
        description:      group.description || `MITRE ATT&CK Group ${groupId}`,
        motivation:       _guessMotivationFromMITRE(group),
        sophistication:   _guessSophFromTTPs(ttps),
        origin_country:   country,
        last_seen:        group.modified || new Date().toISOString(),
        active_since:     group.created  || null,
        aliases:          (group.aliases || []).filter(a => a !== group.name).slice(0, 5),
        ttps,
        tools:            [],
        malware:          [],
        target_sectors:   [],
        target_countries: [],
        tags:             ['mitre', 'apt', groupId].filter(Boolean),
        confidence:       90,
        source:           'mitre',
        external_id:      `mitre:${groupId}`,
        updated_at:       new Date().toISOString(),
      };

      const { error } = await supabaseAdmin
        .from('threat_actors')
        .upsert(row, { onConflict: 'tenant_id,name', ignoreDuplicates: false });

      if (!error) {
        inserted++;
        processed.push(group.name);
      }
    }

    res.json({
      success:         true,
      actors_ingested: inserted,
      groups_total:    groups.length,
      sample:          processed.slice(0, 10),
      duration_ms:     Date.now() - t0,
      source:          'mitre',
    });

  } catch (err) {
    console.error('[Threat-Actors][MITRE Ingest] Error:', err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
}));

/**
 * POST /api/threat-actors/ingest/threatfox
 * Pull actor tags from ThreatFox IOCs to enrich actor profiles.
 * No auth required.
 */
router.post('/ingest/threatfox', verifyToken, requireRole(['ADMIN','SUPER_ADMIN']), asyncHandler(async (req, res) => {
  const tid = tenantId(req);
  const t0  = Date.now();

  try {
    const resp = await axios.post(
      'https://threatfox-api.abuse.ch/api/v1/',
      JSON.stringify({ query: 'get_iocs', days: 7 }),
      {
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'wadjet-eye-ai/5.3' },
        timeout: 30000,
        validateStatus: null,
      }
    );

    if (resp.status !== 200) {
      return res.status(502).json({ success: false, error: `ThreatFox returned HTTP ${resp.status}` });
    }

    const iocs = resp.data?.data || [];

    // Build actor → malware family mapping
    const actorMalware = new Map();
    for (const ioc of iocs) {
      const actor = ioc.threat_actor || ioc.reporter || null;
      if (!actor) continue;
      if (!actorMalware.has(actor)) actorMalware.set(actor, new Set());
      if (ioc.malware) actorMalware.get(actor).add(ioc.malware);
    }

    let updated = 0;
    for (const [actorName, malwareSet] of actorMalware) {
      if (!actorName || actorName.length < 3) continue;

      // Try to update existing actor or insert new minimal one
      const malwareList = [...malwareSet].slice(0, 10);

      const { data: existing } = await supabaseAdmin
        .from('threat_actors')
        .select('id, malware, tags')
        .eq('tenant_id', tid)
        .ilike('name', actorName)
        .maybeSingle();

      if (existing) {
        const merged = [...new Set([...(existing.malware || []), ...malwareList])].slice(0, 20);
        await supabaseAdmin
          .from('threat_actors')
          .update({ malware: merged, updated_at: new Date().toISOString() })
          .eq('id', existing.id);
      } else {
        await supabaseAdmin
          .from('threat_actors')
          .upsert({
            tenant_id:   tid,
            name:        actorName,
            malware:     malwareList,
            tags:        ['threatfox'],
            confidence:  50,
            source:      'threatfox',
            ttps:        [],
            tools:       [],
            aliases:     [],
            target_sectors:   [],
            target_countries: [],
          }, { onConflict: 'tenant_id,name', ignoreDuplicates: true });
      }
      updated++;
    }

    res.json({
      success:        true,
      actors_updated: updated,
      iocs_scanned:   iocs.length,
      duration_ms:    Date.now() - t0,
      source:         'threatfox',
    });

  } catch (err) {
    console.error('[Threat-Actors][ThreatFox Ingest] Error:', err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
}));

// ══════════════════════════════════════════════════════════════════
//  PRIVATE HELPERS — heuristic classification
// ══════════════════════════════════════════════════════════════════

function _guessMotivation(tags = []) {
  const t = tags.map(x => x.toLowerCase()).join(' ');
  if (t.includes('ransomware') || t.includes('ransom'))  return 'ransomware';
  if (t.includes('espionage')  || t.includes('apt'))     return 'espionage';
  if (t.includes('financial')  || t.includes('banking')) return 'financial';
  if (t.includes('hacktivism') || t.includes('activist')) return 'hacktivism';
  if (t.includes('sabotage')   || t.includes('wiper'))   return 'sabotage';
  if (t.includes('crime')      || t.includes('fraud'))   return 'cyber-crime';
  return 'unknown';
}

function _guessSophistication(tags = [], tlp = '') {
  const t = tags.map(x => x.toLowerCase()).join(' ');
  if (t.includes('apt')  || t.includes('nation') || t.includes('state')) return 'nation-state';
  if (t.includes('advanced')  || tlp === 'RED')  return 'advanced';
  if (t.includes('crimeware') || t.includes('kit'))  return 'intermediate';
  return 'medium';
}

function _guessCountry(tags = [], adversary = '') {
  const combined = [...tags, adversary || ''].join(' ').toLowerCase();
  const map = {
    'russia':  'RU', 'fancy bear':'RU', 'cozy bear':'RU', 'sandworm':'RU',
    'china':   'CN', 'apt10':'CN', 'apt41':'CN', 'unit 61398':'CN',
    'north korea': 'KP', 'lazarus':'KP', 'kimsuky':'KP',
    'iran':    'IR', 'apt33':'IR', 'charming kitten':'IR',
    'usa':     'US', 'equation group':'US',
    'israel':  'IL', 'unitedkingdom': 'GB', 'united kingdom': 'GB',
    'vietnam': 'VN', 'apt32':'VN',
    'india':   'IN', 'transparent tribe':'PK',
    'pakistan':'PK',
  };
  for (const [key, country] of Object.entries(map)) {
    if (combined.includes(key)) return country;
  }
  return null;
}

function _guessMotivationFromMITRE(group) {
  const desc = (group.description || '').toLowerCase();
  if (desc.includes('espionage') || desc.includes('intelligence')) return 'espionage';
  if (desc.includes('financial') || desc.includes('theft'))        return 'financial';
  if (desc.includes('disrupt')   || desc.includes('destabi'))      return 'sabotage';
  if (desc.includes('ransomware'))                                  return 'ransomware';
  return 'espionage'; // most MITRE groups are APT/espionage
}

function _guessSophFromTTPs(ttps = []) {
  if (ttps.length >= 10) return 'nation-state';
  if (ttps.length >= 5)  return 'advanced';
  if (ttps.length >= 2)  return 'intermediate';
  return 'medium';
}

function _extractCountryFromGroup(group) {
  const text = [
    group.description || '',
    ...(group.aliases || []),
    group.name || '',
  ].join(' ').toLowerCase();

  const countryMap = {
    'russia': 'RU', 'russian': 'RU', 'cozy bear': 'RU', 'fancy bear': 'RU',
    'sandworm': 'RU', 'gamaredon': 'RU', 'lazyscripter': 'RU',
    'china': 'CN', 'chinese': 'CN', 'apt10': 'CN', 'apt41': 'CN',
    'mustang panda': 'CN', 'menupass': 'CN', 'comment crew': 'CN',
    'north korea': 'KP', 'north korean': 'KP', 'lazarus': 'KP',
    'kimsuky': 'KP', 'temp.hermit': 'KP', 'andariel': 'KP',
    'iran': 'IR', 'iranian': 'IR', 'charming kitten': 'IR',
    'apt33': 'IR', 'apt34': 'IR', 'oilrig': 'IR',
    'vietnam': 'VN', 'vietnamese': 'VN', 'apt32': 'VN', 'ocean lotus': 'VN',
    'pakistan': 'PK', 'transparent tribe': 'PK',
    'india': 'IN', 'sidewinder': 'IN',
    'israel': 'IL', 'united states': 'US', 'american': 'US',
    'equation group': 'US', 'tailored access': 'US',
  };

  for (const [key, cc] of Object.entries(countryMap)) {
    if (text.includes(key)) return cc;
  }
  return null;
}

module.exports = router;
