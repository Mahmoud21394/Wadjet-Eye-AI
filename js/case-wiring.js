/**
 * ══════════════════════════════════════════════════════════════════════
 *  Case Management Wiring — Production Data Binding  v1.0
 *  Wadjet-Eye AI Platform
 *
 *  REPLACES: Static mock CASES array in advanced.js
 *
 *  DATA FLOW (fully wired):
 *    RAYKAN CSDE.analyzeEvents()
 *      → S.incidents / S.detections / S.timeline / S.chains
 *        → _gesIngestResult() → GES (Graph Entity Store)
 *          → CaseMgr.ingestFromRAYKAN(result)
 *            → CaseMgr._STORE[] (live case objects)
 *              → renderCaseManagement() / openCaseDetail()
 *
 *  BIDIRECTIONAL LINKS:
 *    Case ↔ Incident (case.incidentId / case.incidentSummary)
 *    Case ↔ Detections (case.detectionIds[] / case._detections[])
 *    Case ↔ Timeline (case.timelineIds[] / case._timeline[])
 *    Case ↔ Attack Chain (case.chainId / case._chain)
 *    Case ↔ Raw Events (case._rawEvents[])
 *    Detection ↔ Case (det._caseId)
 *    Incident ↔ Case (inc._caseId)
 *
 *  BRIDGES DEFINED:
 *    window.createCaseFromFinding(row)    — from live-detections-soc.js
 *    window.createCaseFromIncident(inc)   — from RAYKAN incident card
 *    window.createCaseFromDetection(det)  — from RAYKAN detection card
 *    CaseMgr.ingestFromRAYKAN(result)     — auto-ingestion hook
 *    renderCaseManagement()               — replaces advanced.js mock renderer
 * ══════════════════════════════════════════════════════════════════════
 */

(function (window) {
  'use strict';

  // ── Case store ─────────────────────────────────────────────────────────
  // Single source of truth. Replaces the static CASES[] array.
  const _STORE = [];          // Array<CaseRecord>
  let   _seqNum = 0;          // Auto-incrementing counter for case IDs

  // ── SLA table by severity ──────────────────────────────────────────────
  const SLA_HOURS = { CRITICAL: 4, HIGH: 12, MEDIUM: 48, LOW: 120, INFORMATIONAL: 240 };

  // ── Helpers ────────────────────────────────────────────────────────────
  function _uid() {
    return (typeof crypto !== 'undefined' && crypto.randomUUID)
      ? crypto.randomUUID()
      : Math.random().toString(36).slice(2) + Date.now().toString(36);
  }

  function _esc(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function _ago(ts) {
    if (!ts) return '—';
    const d = typeof ts === 'number' ? ts : Date.parse(ts);
    if (!d) return '—';
    const s = Math.floor((Date.now() - d) / 1000);
    if (s < 60)   return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s/60)}m ago`;
    if (s < 86400)return `${Math.floor(s/3600)}h ago`;
    return `${Math.floor(s/86400)}d ago`;
  }

  function _slaLabel(createdAt, severity) {
    const hours = SLA_HOURS[(severity||'MEDIUM').toUpperCase()] || 24;
    const deadline = new Date(createdAt).getTime() + hours * 3600_000;
    const remaining = deadline - Date.now();
    if (remaining <= 0) return 'OVERDUE';
    const h = Math.floor(remaining / 3600_000);
    if (h < 1) return `${Math.floor(remaining / 60_000)}m remaining`;
    return `${h}h remaining`;
  }

  function _currentUser() {
    return (typeof CURRENT_USER !== 'undefined' && CURRENT_USER)
      ? (CURRENT_USER.name || CURRENT_USER.email || 'SOC Analyst')
      : 'SOC Analyst';
  }

  function _normSev(s) {
    const m = { critical:'CRITICAL', high:'HIGH', medium:'MEDIUM', low:'LOW', informational:'INFORMATIONAL' };
    return m[(s||'').toLowerCase()] || (s||'MEDIUM').toUpperCase();
  }

  function _caseId() {
    _seqNum++;
    return `CASE-${String(_seqNum).padStart(4, '0')}`;
  }

  // ── Build a CaseRecord from a RAYKAN incident ─────────────────────────
  // FIX v20: Updated linking strategy based on actual CSDE incidentSummary shape.
  //
  // CSDE incidentSummary fields for linking:
  //   inc.id / inc.incidentId  — incident ID
  //   inc.allHosts[]           — all affected hosts
  //   inc.allUsers[]           — all affected users
  //   inc.allSrcIps[]          — all source IPs
  //   inc.killChainStages[]    — each stage has .ruleId
  //   inc.attackChainId        — links to chain
  //   inc.aceScore             — object {score, severityBand, reasons}
  //
  // Detection fields for linking:
  //   d._incidentId            — direct back-link set by CSDE (most reliable)
  //   d.ruleId                 — matches killChainStages[].ruleId
  //   d.host / d.computer      — matches inc.allHosts[]
  //
  // Timeline fields for linking:
  //   t.computer / t.host      — matches inc.allHosts[]
  //   t.batchDetection         — matches d.id of linked detection
  //   t.aggDetection           — same purpose
  function _buildCaseFromIncident(inc, result) {
    const id        = inc.id || inc.incidentId || _uid();
    const severity  = _normSev(inc.severity || 'MEDIUM');
    const now       = Date.now();

    // Build lookup sets for efficient matching
    const incHosts   = new Set([...(inc.allHosts || []), inc.host].filter(Boolean));
    const incUsers   = new Set([...(inc.allUsers || []), inc.user].filter(Boolean));
    const incSrcIps  = new Set([...(inc.allSrcIps || [])].filter(Boolean));
    // RuleIds from kill-chain stages (the authoritative link from CSDE)
    const incRuleIds = new Set(
      (inc.killChainStages || inc.phaseTimeline || [])
        .map(s => s.ruleId || s.detection?.ruleId)
        .filter(Boolean)
    );

    // ── Collect linked detections ──────────────────────────────────────
    // Priority: direct _incidentId back-link → ruleId match → host+user match
    const linkedDets = (result && result.detections)
      ? (result.detections).filter(d => {
          // 1. Direct back-link set by CSDE engine
          if (d._incidentId === id)                              return true;
          // 2. Explicit detectionIds list (if present in some backend shapes)
          if ((inc.detectionIds || []).includes(d.id))          return true;
          // 3. ruleId present in kill-chain stage ruleIds
          if (incRuleIds.size && d.ruleId && incRuleIds.has(d.ruleId)) return true;
          // 4. Shared host + user (same entity cluster) — broadest fallback
          const dHost = d.host || d.computer || d.Computer || '';
          const dUser = d.user || d.User || '';
          if (dHost && incHosts.has(dHost) && dUser && incUsers.has(dUser)) return true;
          // 5. If only one host, match on host alone (single-host scenario)
          if (incHosts.size === 1 && dHost && incHosts.has(dHost))         return true;
          return false;
        })
      : [];

    // ── Collect linked timeline entries ───────────────────────────────
    // Link by: direct host match | batchDetection/aggDetection match with linked det
    const linkedDetIds = new Set(linkedDets.map(d => d.id).filter(Boolean));
    const linkedTimeline = (result && result.timeline)
      ? result.timeline.filter(t => {
          // 1. batchDetection / aggDetection matches a linked detection id
          if (t.batchDetection && linkedDetIds.has(t.batchDetection)) return true;
          if (t.aggDetection   && linkedDetIds.has(t.aggDetection))   return true;
          if (t.detectionId    && linkedDetIds.has(t.detectionId))    return true;
          // 2. Same host as incident
          const tHost = t.computer || t.host || t.entity || '';
          if (tHost && incHosts.has(tHost))                            return true;
          return false;
        })
      : [];

    // ── Find matching attack chain ────────────────────────────────────
    const linkedChain = (result && result.chains)
      ? (result.chains).find(c =>
          c.incidentId === id       ||
          c.id         === id       ||
          c.id         === (inc.attackChainId || '') ||
          (c.stages || []).some(st =>
            linkedDetIds.has(st.detectionId) ||
            (st.ruleId && incRuleIds.has(st.ruleId))
          )
        )
      : null;

    // ── Collect raw events from linked detections ─────────────────────
    const rawEvents = linkedDets.flatMap(d =>
      (d.evidence || d.raw_detections || d.rawEvents || []).slice(0, 10)
    );

    // ── Build MITRE tags ──────────────────────────────────────────────
    // inc.techniques[] and inc.mitreTactics[] are the canonical arrays in CSDE
    const mitreTags = Array.from(new Set([
      ...(inc.mitreTactics    || inc.tactics      || []),
      ...(inc.techniques      || inc.mitreTechniques || []),
      ...(inc.mitreMappings   || []).map(m => m.technique || m.id).filter(Boolean),
      ...linkedDets.flatMap(d => [
        d.mitreTactic, d.mitreTechnique,
        d.mitre?.tactic, d.mitre?.technique,
        d.technique,
      ].filter(Boolean)),
    ])).filter(Boolean).slice(0, 16);

    // ── Build affected assets ─────────────────────────────────────────
    const assets = Array.from(new Set([
      ...incHosts,
      ...incUsers,
      ...incSrcIps,
    ])).filter(Boolean).slice(0, 20);

    // ── Build tags ────────────────────────────────────────────────────
    const tags = [
      ...(inc.mitreTactics || inc.techniques || []).slice(0, 3),
      severity.toLowerCase(),
      inc.behaviorTitle || inc.behavior || '',
      linkedChain ? (linkedChain.type || 'chain') : '',
    ].filter(Boolean).slice(0, 8);

    // ── Resolve aceScore (CSDE returns it as object {score,…}) ───────
    const aceScoreRaw = inc.aceScore;
    const aceScore = (aceScoreRaw && typeof aceScoreRaw === 'object')
      ? aceScoreRaw.score
      : (typeof aceScoreRaw === 'number' ? aceScoreRaw : null);

    // ── Initial system note ───────────────────────────────────────────
    const phaseStr = (inc.killChainStages || inc.phaseTimeline || [])
      .map(p => p.tactic || p.mitreTactic || p.phase || String(p))
      .filter(Boolean).join(' → ') || '—';

    const notes = [{
      user: 'RAYKAN Engine',
      time: new Date().toISOString(),
      isSystem: true,
      text: `Auto-created from RAYKAN pipeline. Incident ${id} — ` +
            `${inc.behaviorTitle || inc.behavior || inc.title || 'Unknown Behavior'} · ` +
            `${linkedDets.length} detection(s) · ACE Score: ${aceScore ?? '—'} · ` +
            `Confidence: ${inc.level || inc.forensicConfidence || '—'} · ` +
            `Verdict: ${inc.verdict || '—'} · ` +
            `Phase Chain: ${phaseStr}`,
    }];

    // Add narrative as a system note (CSDE enriched attack narrative)
    const narrativeText = inc.narrative || inc.description || inc.rootCauseSummary || '';
    if (narrativeText) {
      notes.push({
        user: 'RAYKAN Engine',
        time: new Date().toISOString(),
        isSystem: true,
        text: `📋 ${narrativeText}`,
      });
    }
    // Add verdict note if available
    if (inc.verdict) {
      notes.push({
        user: 'RAYKAN Engine',
        time: new Date().toISOString(),
        isSystem: true,
        text: `🔬 Verdict: ${inc.verdict} — ${inc.verdictReason || ''}`,
      });
    }

    const caseRecord = {
      // ── Core identity ───────────────────────────────────────────
      id          : _caseId(),
      uuid        : _uid(),
      title       : inc.title || inc.behaviorTitle || inc.name || inc.behavior || `Incident: ${id.slice(0, 12)}`,
      severity,
      status      : 'Open',
      assignee    : _currentUser(),
      createdAt   : now,
      updatedAt   : now,
      sla         : _slaLabel(now, severity),
      tags,
      notes,

      // ── Bidirectional RAYKAN links ──────────────────────────────
      incidentId      : id,
      incidentSummary : inc,
      detectionIds    : linkedDets.map(d => d.id).filter(Boolean),
      timelineIds     : linkedTimeline.map(t => t.id).filter(Boolean),
      chainId         : linkedChain?.id || null,

      // ── Resolved objects (for detail view) ─────────────────────
      _detections  : linkedDets,
      _timeline    : linkedTimeline,
      _chain       : linkedChain || null,
      _rawEvents   : rawEvents.slice(0, 50),
      _assets      : assets,
      _mitreTags   : mitreTags,

      // ── Risk / confidence metrics ───────────────────────────────
      // aceScore is an object {score,severityBand,reasons} from CSDE — unwrap it
      aceScore     : aceScore,
      riskScore    : inc.riskScore ?? inc.progressiveRisk ?? aceScore ?? null,
      confidence   : inc.level       || inc.forensicConfidence || '—',
      behavior     : inc.behaviorTitle || inc.behavior || inc.title || '—',
      alertCount   : linkedDets.length || inc.detectionCount || 1,

      // ── Phase chain for overview tab ────────────────────────────
      // inc.killChainStages has: {ruleId, detection_name, tactic, technique,
      //   mitreTactic, timestamp, observed, riskScore, confidence, inferred}
      phaseChain   : (inc.killChainStages || inc.phaseTimeline || []).map(p => ({
        phase      : p.tactic || p.mitreTactic || p.phase || String(p),
        technique  : p.technique || p.mitreTechnique || '',
        observed   : p.observed !== false && !p.inferred,
        confidence : p.confidence ?? p.riskScore ?? null,
        ruleId     : p.ruleId     || '',
        label      : p.detection_name || p.label || '',
      })),

      // ── Source tracking ─────────────────────────────────────────
      source       : 'raykan',
      sessionId    : (result && result.sessionId) || null,
    };

    return caseRecord;
  }

  // ── Build a case from a single detection (SOC finding) ────────────────
  function _buildCaseFromFinding(det) {
    const severity = _normSev(det.severity || det.sev || 'MEDIUM');
    const now      = Date.now();

    const notes = [{
      user     : 'SOC Analyst',
      time     : new Date().toISOString(),
      isSystem : true,
      text     : `Case created from detection: ${det.rule || det.ruleName || det.name || det.detection_name || 'Alert'} · ` +
                 `Host: ${det.host || det.computer || det.Computer || det.hostname || '—'} · ` +
                 `User: ${det.user || det.User || '—'}`,
    }];

    return {
      id          : _caseId(),
      uuid        : _uid(),
      title       : det.title || det.ruleName || det.rule || det.detection_name || det.name || 'Security Alert',
      severity,
      status      : 'Open',
      assignee    : _currentUser(),
      createdAt   : now,
      updatedAt   : now,
      sla         : _slaLabel(now, severity),
      tags        : [severity.toLowerCase(), det.mitreTactic, det.category].filter(Boolean).slice(0, 6),
      notes,

      incidentId      : det.incidentId || null,
      incidentSummary : null,
      detectionIds    : [det.id].filter(Boolean),
      timelineIds     : [],
      chainId         : null,

      _detections  : [det],
      _timeline    : [],
      _chain       : null,
      _rawEvents   : (det.evidence || det.raw_detections || []).slice(0, 20),
      _assets      : [det.host || det.computer || det.Computer, det.user || det.User, det.srcIp].filter(Boolean),
      _mitreTags   : [det.mitreTactic, det.mitreTechnique].filter(Boolean),

      aceScore     : null,
      riskScore    : det.riskScore ?? null,
      confidence   : '—',
      behavior     : det.category || det.mitreTactic || '—',
      alertCount   : 1,
      phaseChain   : [],
      source       : 'finding',
      sessionId    : null,
    };
  }

  // ══════════════════════════════════════════════════════════════════════
  //  PUBLIC API — CaseMgr
  // ══════════════════════════════════════════════════════════════════════
  const CaseMgr = {

    // ── Return a copy of the store ──────────────────────────────────────
    getCases() { return _STORE.slice(); },

    // ── Find a single case ──────────────────────────────────────────────
    findById(id) { return _STORE.find(c => c.id === id) || null; },

    // ── Find case linked to an incident ────────────────────────────────
    findByIncidentId(incidentId) {
      return _STORE.find(c => c.incidentId === incidentId) || null;
    },

    // ── Find cases linked to a detection ───────────────────────────────
    findByDetectionId(detId) {
      return _STORE.filter(c => c.detectionIds.includes(detId));
    },

    // ── Reset store (call before re-ingesting a full result) ─────────
    reset() {
      _STORE.length = 0;
      _seqNum = 0;
    },

    // ── Ingest a full CSDE/RAYKAN result and auto-create cases ────────
    // Called after CSDE.analyzeEvents() returns a result.
    // Produces one case per incident; if the incident already has a case
    // (matched by incidentId) it is updated in-place rather than duplicated.
    ingestFromRAYKAN(result) {
      if (!result) return;

      const incidents = [];
      if (Array.isArray(result.incidentSummaries) && result.incidentSummaries.length) {
        incidents.push(...result.incidentSummaries);
      } else if (Array.isArray(result.incidents) && result.incidents.length) {
        incidents.push(...result.incidents);
      }

      let created = 0, updated = 0;

      incidents.forEach(inc => {
        const incId = inc.id || inc.incidentId;
        if (!incId) return;

        const existing = CaseMgr.findByIncidentId(incId);
        if (existing) {
          // Update existing case with latest incident data
          Object.assign(existing, {
            severity     : _normSev(inc.severity || existing.severity),
            riskScore    : inc.riskScore   ?? existing.riskScore,
            aceScore     : inc.aceScore    ?? existing.aceScore,
            confidence   : inc.level       || existing.confidence,
            phaseChain   : (inc.phaseTimeline || inc.killChainStages || []).map(p => ({
              phase      : p.tactic || p.phase || String(p),
              technique  : p.technique || '',
              observed   : p.observed !== false,
              confidence : p.confidence ?? p.confidenceScore ?? null,
            })),
            updatedAt    : Date.now(),
            sla          : _slaLabel(existing.createdAt, inc.severity || existing.severity),
            incidentSummary : inc,
          });
          // Merge new detections
          const newDetIds = (result.detections || [])
            .filter(d => d.incidentId === incId)
            .map(d => d.id).filter(Boolean);
          const merged = Array.from(new Set([...existing.detectionIds, ...newDetIds]));
          existing.detectionIds = merged;
          existing.alertCount   = merged.length || existing.alertCount;
          updated++;
        } else {
          const c = _buildCaseFromIncident(inc, result);
          // back-link: stamp _caseId on detection / incident objects
          c._detections.forEach(d => { d._caseId = c.id; });
          if (inc) inc._caseId = c.id;
          _STORE.unshift(c);
          created++;
        }
      });

      // If pipeline produced ONLY detections (no incidents formed yet),
      // do not auto-create cases — analyst must escalate manually.

      if (created || updated) {
        console.info(`[CaseMgr] Ingested RAYKAN result → ${created} case(s) created, ${updated} updated. Store size: ${_STORE.length}`);
        // Refresh Case Management view if it is currently visible
        if (typeof window.renderCaseManagement === 'function') {
          const pg = document.getElementById('page-case-management');
          if (pg && pg.style && pg.style.display !== 'none' && pg.classList.contains('active')) {
            window.renderCaseManagement();
          }
        }
      }

      return { created, updated, total: _STORE.length };
    },

    // ── Manually create a case from a detection row (SOC finding) ──────
    createFromFinding(det) {
      if (!det) return null;
      // Avoid duplication
      const existing = _STORE.find(c =>
        c.detectionIds.includes(det.id) ||
        (det.incidentId && c.incidentId === det.incidentId)
      );
      if (existing) {
        showToast && showToast(`📁 Case ${existing.id} already exists for this detection`, 'info');
        return existing;
      }
      const c = _buildCaseFromFinding(det);
      if (det.id) det._caseId = c.id;
      _STORE.unshift(c);
      console.info(`[CaseMgr] Case ${c.id} created from finding: ${det.id || det.rule}`);
      return c;
    },

    // ── Manually create a case from an incident object ─────────────────
    createFromIncident(inc, result) {
      if (!inc) return null;
      const incId = inc.id || inc.incidentId;
      const existing = incId ? CaseMgr.findByIncidentId(incId) : null;
      if (existing) {
        showToast && showToast(`📁 Case ${existing.id} already linked to this incident`, 'info');
        return existing;
      }
      const r = result || (window.RAYKAN_UI ? window.RAYKAN_UI.getState() : null);
      const c = _buildCaseFromIncident(inc, r);
      c._detections.forEach(d => { d._caseId = c.id; });
      if (inc) inc._caseId = c.id;
      _STORE.unshift(c);
      console.info(`[CaseMgr] Case ${c.id} created from incident: ${incId}`);
      return c;
    },

    // ── Add a note to a case ───────────────────────────────────────────
    addNote(caseId, text, user) {
      const c = CaseMgr.findById(caseId);
      if (!c || !text?.trim()) return false;
      c.notes.unshift({
        user     : user || _currentUser(),
        time     : new Date().toISOString(),
        isSystem : false,
        text     : text.trim(),
      });
      c.updatedAt = Date.now();
      return true;
    },

    // ── Update case status ─────────────────────────────────────────────
    updateStatus(caseId, status) {
      const c = CaseMgr.findById(caseId);
      if (!c) return false;
      c.status    = status;
      c.updatedAt = Date.now();
      if (status === 'Resolved') {
        c.notes.unshift({
          user: _currentUser(), time: new Date().toISOString(), isSystem: true,
          text: `Case resolved by ${_currentUser()}.`,
        });
      }
      return true;
    },

    // ── Update assignee ────────────────────────────────────────────────
    updateAssignee(caseId, assignee) {
      const c = CaseMgr.findById(caseId);
      if (!c) return false;
      c.assignee  = assignee;
      c.updatedAt = Date.now();
      return true;
    },

    // ── Export cases as JSON ───────────────────────────────────────────
    exportJSON() {
      return JSON.stringify(_STORE.map(c => ({
        id: c.id, title: c.title, severity: c.severity, status: c.status,
        assignee: c.assignee, createdAt: new Date(c.createdAt).toISOString(),
        incidentId: c.incidentId, detectionIds: c.detectionIds, chainId: c.chainId,
        aceScore: c.aceScore, riskScore: c.riskScore, confidence: c.confidence,
        behavior: c.behavior, tags: c.tags, alertCount: c.alertCount,
        phaseChain: c.phaseChain.map(p => p.phase),
        mitreTags: c._mitreTags, assets: c._assets,
      })), null, 2);
    },
  };

  // ══════════════════════════════════════════════════════════════════════
  //  CASE MANAGEMENT UI RENDERER
  //  Replaces renderCaseManagement() in advanced.js (which uses mock CASES[])
  // ══════════════════════════════════════════════════════════════════════

  const STATUS_COLORS = {
    Open:'#ef4444', 'In Progress':'#f59e0b', Investigating:'#3b82f6',
    Escalated:'#ec4899', Monitoring:'#22d3ee', Resolved:'#22c55e',
  };

  function _sevColor(sev) {
    const m = { CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#f59e0b', LOW:'#22c55e', INFORMATIONAL:'#6b7280' };
    return m[(sev||'').toUpperCase()] || '#6b7280';
  }

  function _sevBorder(sev) {
    const m = {
      CRITICAL:'rgba(239,68,68,0.4)', HIGH:'rgba(249,115,22,0.3)',
      MEDIUM:'rgba(245,158,11,0.3)',  LOW:'rgba(34,197,94,0.2)',
    };
    return m[(sev||'').toUpperCase()] || 'var(--border)';
  }

  // ── Filter state ──────────────────────────────────────────────────────
  let _filterStatus = '', _filterSev = '', _currentCaseId = null;

  function _getFiltered() {
    return CaseMgr.getCases().filter(c =>
      (!_filterStatus || c.status === _filterStatus) &&
      (!_filterSev    || c.severity === _filterSev.toUpperCase())
    );
  }

  // ── Main renderer ─────────────────────────────────────────────────────
  function renderCaseManagement() {
    const container = document.getElementById('caseManagementWrap');
    if (!container) return;
    container.style.display = '';

    // Also hide the live-pages container that may co-exist
    const liveCont = document.getElementById('casesLiveContainer');
    if (liveCont) liveCont.style.display = 'none';

    const cases = _getFiltered();
    const all   = CaseMgr.getCases();

    const stats = [
      { label:'Open',        count: all.filter(c=>c.status==='Open').length,        color:'#ef4444' },
      { label:'In Progress', count: all.filter(c=>['In Progress','Investigating','Escalated'].includes(c.status)).length, color:'#f59e0b' },
      { label:'Monitoring',  count: all.filter(c=>c.status==='Monitoring').length,  color:'#3b82f6' },
      { label:'Resolved',    count: all.filter(c=>c.status==='Resolved').length,    color:'#22c55e' },
    ];

    container.innerHTML = `
<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:16px;">
  <div>
    <h2 style="font-size:16px;font-weight:800;">📁 Case Management &amp; Incident Tracking</h2>
    <p style="font-size:11px;color:var(--text-muted);">Live production cases — sourced from RAYKAN detection pipeline · ${all.length} total</p>
  </div>
  <div style="display:flex;gap:6px;flex-wrap:wrap;">
    <select class="filter-select" id="cm-sev-filter" onchange="window._cmApplyFilter()" style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:5px 10px;border-radius:6px;font-size:12px;">
      <option value="">All Severities</option>
      <option value="CRITICAL">Critical</option>
      <option value="HIGH">High</option>
      <option value="MEDIUM">Medium</option>
      <option value="LOW">Low</option>
    </select>
    <select class="filter-select" id="cm-status-filter" onchange="window._cmApplyFilter()" style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:5px 10px;border-radius:6px;font-size:12px;">
      <option value="">All Status</option>
      <option value="Open">Open</option>
      <option value="In Progress">In Progress</option>
      <option value="Investigating">Investigating</option>
      <option value="Escalated">Escalated</option>
      <option value="Monitoring">Monitoring</option>
      <option value="Resolved">Resolved</option>
    </select>
    <button class="btn-primary" onclick="window._cmOpenNewCase()"><i class="fas fa-plus"></i> New Case</button>
    <button class="btn-primary" style="background:var(--bg-elevated);border:1px solid var(--border);color:var(--text-secondary);" onclick="window._cmExport()"><i class="fas fa-download"></i> Export</button>
  </div>
</div>

<!-- Stats Bar -->
<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:8px;margin-bottom:16px;">
  ${stats.map(s => `
  <div style="background:${s.color}15;border:1px solid ${s.color}33;border-radius:8px;padding:10px;text-align:center;">
    <div style="font-size:24px;font-weight:900;color:${s.color};">${s.count}</div>
    <div style="font-size:10px;color:var(--text-muted);">${s.label}</div>
  </div>`).join('')}
  <div style="background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.3);border-radius:8px;padding:10px;text-align:center;">
    <div style="font-size:24px;font-weight:900;color:#60a5fa;">${all.length}</div>
    <div style="font-size:10px;color:var(--text-muted);">Total Cases</div>
  </div>
</div>

<!-- Empty State -->
${cases.length === 0 ? `
<div style="text-align:center;padding:60px 20px;color:#4b5563;">
  <div style="font-size:36px;margin-bottom:12px;">📂</div>
  <div style="font-size:15px;color:#6b7280;margin-bottom:8px;">
    ${all.length === 0
      ? 'No cases yet — run RAYKAN to auto-generate cases from detections.'
      : 'No cases match the current filter.'}
  </div>
  ${all.length === 0 ? `
  <div style="font-size:12px;color:#374151;">
    Go to <button onclick="if(typeof navigateTo==='function')navigateTo('raykan')"
      style="background:none;border:1px solid #3b82f6;color:#60a5fa;padding:4px 12px;border-radius:6px;cursor:pointer;font-size:12px;">
      RAYKAN Threat Hunting</button> → run a demo or upload logs → cases are created automatically.
  </div>` : ''}
</div>` : ''}

<!-- Cases Grid -->
<div id="casesGrid" style="display:flex;flex-direction:column;gap:10px;">
  ${cases.map(c => _renderCaseCard(c)).join('')}
</div>`;

    // Restore filter selectors
    const sevEl = document.getElementById('cm-sev-filter');
    const stEl  = document.getElementById('cm-status-filter');
    if (sevEl) sevEl.value = _filterSev;
    if (stEl)  stEl.value  = _filterStatus;
  }

  // ── Render a single case card ─────────────────────────────────────────
  function _renderCaseCard(c) {
    const sc      = _sevColor(c.severity);
    const stColor = STATUS_COLORS[c.status] || '#64748b';
    const border  = _sevBorder(c.severity);

    const phaseStr = c.phaseChain.filter(p => p.observed).map(p => p.phase).join(' → ') ||
                     (c.behavior !== '—' ? c.behavior : '');

    return `
<div style="background:var(--bg-card);border:1px solid ${border};border-radius:10px;padding:14px;cursor:pointer;transition:all 0.2s ease;"
     onclick="window._cmOpenDetail('${_esc(c.id)}')"
     onmouseover="this.style.borderColor='${stColor}'" onmouseout="this.style.borderColor='${border}'">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
    <div style="flex:1;min-width:200px;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap;">
        <span style="font-size:10px;font-family:monospace;color:var(--accent-cyan);">${_esc(c.id)}</span>
        <span style="font-size:9px;padding:2px 6px;background:${sc}20;color:${sc};border-radius:4px;border:1px solid ${sc}44;font-weight:700;">${_esc(c.severity)}</span>
        <span style="font-size:10px;padding:2px 7px;background:${stColor}20;color:${stColor};border-radius:4px;border:1px solid ${stColor}44;font-weight:700;">${_esc(c.status)}</span>
        ${c.source === 'raykan' ? '<span style="font-size:9px;padding:1px 5px;background:rgba(139,92,246,0.15);color:#a78bfa;border-radius:3px;border:1px solid rgba(139,92,246,0.3);">RAYKAN</span>' : ''}
        ${c.confidence && c.confidence !== '—' ? `<span style="font-size:9px;padding:1px 5px;background:rgba(34,211,238,0.1);color:#22d3ee;border-radius:3px;">${_esc(c.confidence)}</span>` : ''}
      </div>
      <div style="font-size:13px;font-weight:700;margin-bottom:6px;color:#e6edf3;">${_esc(c.title)}</div>
      ${phaseStr ? `<div style="font-size:10px;color:#8b949e;margin-bottom:5px;">⛓ ${_esc(phaseStr)}</div>` : ''}
      <div style="display:flex;flex-wrap:wrap;gap:4px;">
        ${c.tags.map(t => `<span style="font-size:9px;padding:1px 5px;background:rgba(59,130,246,0.1);color:#60a5fa;border-radius:3px;">#${_esc(t)}</span>`).join('')}
      </div>
    </div>
    <div style="text-align:right;flex-shrink:0;">
      <div style="font-size:11px;font-weight:600;">${_esc(c.assignee)}</div>
      <div style="font-size:10px;color:var(--text-muted);">Assigned to</div>
      ${c.riskScore != null ? `<div style="font-size:11px;margin-top:3px;color:${c.riskScore>=80?'#ef4444':c.riskScore>=60?'#f97316':c.riskScore>=40?'#eab308':'#22c55e'};font-weight:700;">Risk: ${c.riskScore}</div>` : ''}
      <div style="font-size:10px;margin-top:4px;color:${c.sla==='OVERDUE'?'#ef4444':'#f59e0b'};font-weight:700;">⏰ ${_esc(c.sla)}</div>
    </div>
  </div>
  <div style="display:flex;align-items:center;justify-content:space-between;margin-top:10px;padding-top:10px;border-top:1px solid var(--border);">
    <div style="display:flex;gap:10px;font-size:10px;color:var(--text-muted);">
      <span><i class="fas fa-crosshairs"></i> ${c.alertCount} detection${c.alertCount!==1?'s':''}</span>
      <span><i class="fas fa-comment"></i> ${c.notes.length} note${c.notes.length!==1?'s':''}</span>
      ${c.incidentId ? `<span style="color:#a78bfa;"><i class="fas fa-link"></i> INC linked</span>` : ''}
      ${c.chainId    ? `<span style="color:#22d3ee;"><i class="fas fa-sitemap"></i> Chain linked</span>` : ''}
      <span><i class="fas fa-clock"></i> ${_ago(c.updatedAt)}</span>
    </div>
    <div style="display:flex;gap:4px;" onclick="event.stopPropagation()">
      <button class="tbl-btn" title="Escalate"
        onclick="window._cmEscalate('${_esc(c.id)}')"><i class="fas fa-arrow-up"></i></button>
      <button class="tbl-btn" title="In Progress"
        onclick="window._cmInProgress('${_esc(c.id)}')"><i class="fas fa-play"></i></button>
      <button class="tbl-btn" title="Resolve"
        onclick="window._cmResolve('${_esc(c.id)}')"><i class="fas fa-check"></i></button>
      ${c.incidentId ? `<button class="tbl-btn" title="Go to RAYKAN incident"
        onclick="window._cmViewInRAYKAN('${_esc(c.incidentId)}')"><i class="fas fa-external-link-alt"></i></button>` : ''}
    </div>
  </div>
</div>`;
  }

  // ── Case Detail Modal ─────────────────────────────────────────────────
  function _openCaseDetail(id) {
    const c = CaseMgr.findById(id);
    if (!c) return;
    _currentCaseId = id;
    const stColor = STATUS_COLORS[c.status] || '#64748b';
    const sc      = _sevColor(c.severity);

    const overviewHtml = _renderDetailOverview(c, stColor, sc);
    const detectionsHtml = _renderDetailDetections(c);
    const timelineHtml   = _renderDetailTimeline(c);
    const chainHtml      = _renderDetailChain(c);
    const notesHtml      = _renderDetailNotes(c);

    // FIX v20: openDetailModal() injects this into #detailModalBody, which lives
    // inside #detailModalContent (.modal-card.large). switchModalTab() uses
    // btn.closest('.modal-card') to scope tab switching — so we must NOT add
    // another .modal-card here (that would create a nested match).
    // Instead, use a plain data-scoped container so switchModalTab's updated
    // selector (#detailModalBody) can scope correctly.
    const html = `
<div id="cmDetailRoot">
  <div style="margin-bottom:12px;">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px;">
      <span style="font-size:10px;font-family:monospace;color:var(--accent-cyan);">${_esc(c.id)}</span>
      ${c.incidentId ? `<span style="font-size:10px;font-family:monospace;color:#a78bfa;">INC: ${_esc(c.incidentId.slice(0,16))}</span>` : ''}
      <span style="font-size:9px;padding:2px 7px;background:${sc}20;color:${sc};border-radius:4px;border:1px solid ${sc}44;font-weight:700;">${_esc(c.severity)}</span>
      <span style="font-size:9px;padding:2px 7px;background:${stColor}20;color:${stColor};border-radius:4px;border:1px solid ${stColor}44;font-weight:700;">${_esc(c.status)}</span>
      ${c.source === 'raykan' ? '<span style="font-size:9px;padding:1px 6px;background:rgba(139,92,246,0.15);color:#a78bfa;border-radius:3px;border:1px solid rgba(139,92,246,0.3);">RAYKAN</span>' : ''}
    </div>
    <div style="font-size:16px;font-weight:800;color:#e6edf3;">${_esc(c.title)}</div>
    ${c.behavior && c.behavior !== '—' ? `<div style="font-size:11px;color:#8b949e;margin-top:3px;">Behavior: ${_esc(c.behavior)}</div>` : ''}
  </div>

  <div class="modal-tabs" style="display:flex;gap:3px;flex-wrap:wrap;border-bottom:1px solid #21262d;padding-bottom:10px;margin-bottom:14px;">
    <button class="modal-tab active" onclick="switchModalTab(this,'cmtab-overview')">📋 Overview</button>
    <button class="modal-tab" onclick="switchModalTab(this,'cmtab-detections')">🎯 Detections <span style="font-size:9px;background:rgba(239,68,68,0.15);color:#ef4444;padding:1px 5px;border-radius:3px;margin-left:2px;">${c.alertCount}</span></button>
    <button class="modal-tab" onclick="switchModalTab(this,'cmtab-timeline')">⏱ Timeline <span style="font-size:9px;background:rgba(59,130,246,0.15);color:#60a5fa;padding:1px 5px;border-radius:3px;margin-left:2px;">${c._timeline.length}</span></button>
    <button class="modal-tab" onclick="switchModalTab(this,'cmtab-chain')">⛓ Attack Chain</button>
    <button class="modal-tab" onclick="switchModalTab(this,'cmtab-notes')">📝 Notes <span style="font-size:9px;background:rgba(34,197,94,0.15);color:#22c55e;padding:1px 5px;border-radius:3px;margin-left:2px;">${c.notes.length}</span></button>
  </div>

  <div id="cmtab-overview"    class="modal-tab-panel active">${overviewHtml}</div>
  <div id="cmtab-detections"  class="modal-tab-panel">${detectionsHtml}</div>
  <div id="cmtab-timeline"    class="modal-tab-panel">${timelineHtml}</div>
  <div id="cmtab-chain"       class="modal-tab-panel">${chainHtml}</div>
  <div id="cmtab-notes"       class="modal-tab-panel">${notesHtml}</div>
</div>`;

    // Always use the shared #detailModal infrastructure (openDetailModal defined in main.js v20).
    // If somehow not yet defined (e.g., main.js not loaded), fall back to inline overlay.
    if (typeof openDetailModal === 'function') {
      openDetailModal(html);
    } else {
      // Emergency fallback — should never fire in production
      let ov = document.getElementById('cm-modal-overlay');
      if (!ov) {
        ov = document.createElement('div');
        ov.id = 'cm-modal-overlay';
        ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:9999;display:flex;align-items:center;justify-content:center;';
        ov.onclick = e => { if (e.target === ov) ov.remove(); };
        document.body.appendChild(ov);
      }
      ov.innerHTML = `
<div style="background:#0d1117;border:1px solid #30363d;border-radius:12px;width:820px;max-width:96vw;max-height:90vh;overflow:hidden;position:relative;display:flex;flex-direction:column;">
  <button onclick="document.getElementById('cm-modal-overlay').remove()"
    style="position:absolute;top:10px;right:14px;background:none;border:none;color:#8b949e;font-size:20px;cursor:pointer;z-index:1;">✕</button>
  ${html}
</div>`;
    }
  }

  // ── Detail tab: Overview ──────────────────────────────────────────────
  function _renderDetailOverview(c, stColor, sc) {
    const phaseRows = c.phaseChain.length ? c.phaseChain.map((p, i) => `
<div style="display:flex;align-items:center;gap:8px;padding:6px 8px;background:${p.observed?'rgba(59,130,246,0.07)':'rgba(107,114,128,0.07)'};border-radius:5px;border-left:3px solid ${p.observed?'#3b82f6':'#4b5563'};">
  <span style="font-size:10px;color:#6b7280;width:20px;text-align:right;">${i+1}</span>
  <span style="font-size:12px;color:${p.observed?'#60a5fa':'#6b7280'};font-weight:${p.observed?'700':'400'};">${_esc(p.phase)}</span>
  ${p.technique ? `<span style="font-size:9px;color:#8b949e;font-family:monospace;">${_esc(p.technique)}</span>` : ''}
  <span style="margin-left:auto;font-size:9px;color:${p.observed?'#22c55e':'#4b5563'};">${p.observed?'✓ Observed':'⋯ Inferred'}</span>
  ${p.confidence!=null ? `<span style="font-size:9px;color:#8b949e;">${p.confidence}%</span>` : ''}
</div>`).join('') : '<div style="color:#4b5563;font-size:12px;padding:8px;">No phase chain data.</div>';

    const assetRows = c._assets.length ? c._assets.slice(0,12).map(a =>
      `<span style="font-size:11px;padding:3px 8px;background:rgba(34,211,238,0.08);color:#22d3ee;border-radius:4px;border:1px solid rgba(34,211,238,0.2);">${_esc(a)}</span>`
    ).join('') : '<span style="font-size:11px;color:#4b5563;">—</span>';

    const mitreRows = c._mitreTags.length ? c._mitreTags.map(m =>
      `<span style="font-size:10px;padding:2px 6px;background:rgba(168,85,247,0.1);color:#c084fc;border-radius:3px;border:1px solid rgba(168,85,247,0.25);">${_esc(m)}</span>`
    ).join('') : '<span style="font-size:11px;color:#4b5563;">—</span>';

    return `
<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
  <div style="background:var(--bg-surface,#161b22);border:1px solid var(--border,#21262d);border-radius:8px;padding:12px;">
    <div style="font-size:11px;font-weight:700;color:#8b949e;margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px;">📋 Case Details</div>
    <div style="display:flex;flex-direction:column;gap:6px;font-size:12px;">
      <div style="display:flex;justify-content:space-between;"><span style="color:#6b7280;">Assignee:</span><span style="font-weight:700;">${_esc(c.assignee)}</span></div>
      <div style="display:flex;justify-content:space-between;"><span style="color:#6b7280;">Created:</span><span>${new Date(c.createdAt).toLocaleString()}</span></div>
      <div style="display:flex;justify-content:space-between;"><span style="color:#6b7280;">Updated:</span><span>${_ago(c.updatedAt)}</span></div>
      <div style="display:flex;justify-content:space-between;"><span style="color:#6b7280;">SLA:</span><span style="color:${c.sla==='OVERDUE'?'#ef4444':'#f59e0b'};font-weight:700;">${_esc(c.sla)}</span></div>
      ${c.riskScore!=null?`<div style="display:flex;justify-content:space-between;"><span style="color:#6b7280;">Risk Score:</span><span style="font-weight:700;color:${c.riskScore>=80?'#ef4444':c.riskScore>=60?'#f97316':'#eab308'};">${c.riskScore}</span></div>`:''}
      ${c.aceScore!=null?`<div style="display:flex;justify-content:space-between;"><span style="color:#6b7280;">ACE Score:</span><span style="font-weight:700;color:#a78bfa;">${c.aceScore}</span></div>`:''}
      <div style="display:flex;justify-content:space-between;"><span style="color:#6b7280;">Confidence:</span><span style="font-weight:700;color:#34d399;">${_esc(c.confidence)}</span></div>
      ${c.incidentId?`<div style="display:flex;justify-content:space-between;"><span style="color:#6b7280;">Incident ID:</span><span style="font-family:monospace;font-size:10px;color:#a78bfa;">${_esc(c.incidentId.slice(0,20))}</span></div>`:''}
      ${c.sessionId?`<div style="display:flex;justify-content:space-between;"><span style="color:#6b7280;">Session:</span><span style="font-family:monospace;font-size:10px;color:#8b949e;">${_esc(c.sessionId.slice(0,14))}…</span></div>`:''}
    </div>
  </div>
  <div style="background:var(--bg-surface,#161b22);border:1px solid var(--border,#21262d);border-radius:8px;padding:12px;">
    <div style="font-size:11px;font-weight:700;color:#8b949e;margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px;">🎯 MITRE ATT&CK</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px;">${mitreRows}</div>
    <div style="font-size:11px;font-weight:700;color:#8b949e;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px;">🖥 Affected Assets</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;">${assetRows}</div>
  </div>
</div>

<div style="background:var(--bg-surface,#161b22);border:1px solid var(--border,#21262d);border-radius:8px;padding:12px;margin-bottom:14px;">
  <div style="font-size:11px;font-weight:700;color:#8b949e;margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px;">⛓ Kill Chain / Phase Timeline</div>
  <div style="display:flex;flex-direction:column;gap:4px;">${phaseRows}</div>
</div>

<div style="display:flex;gap:8px;flex-wrap:wrap;">
  <button class="btn-primary" onclick="window._cmReassign('${_esc(c.id)}')"><i class="fas fa-user-tag"></i> Reassign</button>
  <button class="btn-primary" style="background:var(--accent-orange,#f97316);" onclick="window._cmEscalate('${_esc(c.id)}')"><i class="fas fa-arrow-up"></i> Escalate</button>
  <button class="btn-primary" style="background:var(--accent-green,#22c55e);" onclick="window._cmResolve('${_esc(c.id)}');if(typeof closeDetailModal==='function')closeDetailModal()"><i class="fas fa-check"></i> Resolve</button>
  ${c.incidentId ? `<button class="btn-primary" style="background:#7c3aed;" onclick="window._cmViewInRAYKAN('${_esc(c.incidentId)}')"><i class="fas fa-external-link-alt"></i> View in RAYKAN</button>` : ''}
  <button class="btn-export-pdf" onclick="window._cmExportCase('${_esc(c.id)}')"><i class="fas fa-file-pdf"></i> PDF Report</button>
</div>`;
  }

  // ── Detail tab: Detections ────────────────────────────────────────────
  function _renderDetailDetections(c) {
    if (!c._detections.length) {
      return '<div style="color:#4b5563;padding:20px;font-size:12px;">No detections linked to this case.</div>';
    }
    return `<div style="display:flex;flex-direction:column;gap:6px;">
${c._detections.map(d => `
<div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:10px;font-size:12px;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;flex-wrap:wrap;">
    <span style="font-size:9px;padding:2px 6px;background:${_sevColor(d.severity)}20;color:${_sevColor(d.severity)};border-radius:4px;font-weight:700;">${_esc((d.severity||'').toUpperCase())}</span>
    <span style="font-family:monospace;font-size:10px;color:#22d3ee;">${_esc(d.ruleId||d.id||'—')}</span>
    <span style="font-weight:600;color:#e6edf3;">${_esc(d.detection_name||d.ruleName||d.name||'Alert')}</span>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:4px;font-size:11px;color:#8b949e;">
    <span>Host: <strong style="color:#e6edf3;">${_esc(d.host||d.computer||d.Computer||'—')}</strong></span>
    <span>User: <strong style="color:#e6edf3;">${_esc(d.user||d.User||'—')}</strong></span>
    <span>SrcIP: <strong style="color:#e6edf3;">${_esc(d.srcIp||'—')}</strong></span>
    <span>Tactic: <strong style="color:#a78bfa;">${_esc(d.mitreTactic||d.category||'—')}</strong></span>
    <span>Technique: <strong style="color:#c084fc;">${_esc(d.mitreTechnique||'—')}</strong></span>
    <span>Risk: <strong style="color:#f59e0b;">${d.riskScore??'—'}</strong></span>
  </div>
  ${d.commandLine ? `<div style="margin-top:5px;font-size:10px;font-family:monospace;color:#64748b;background:#0a0e14;padding:5px 8px;border-radius:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${_esc((d.commandLine||'').slice(0,120))}</div>` : ''}
  ${d.batchDetection ? `<div style="margin-top:3px;font-size:9px;color:#8b949e;">Aggregated: <span style="color:#22d3ee;font-family:monospace;">${_esc(d.batchDetection)}</span></div>` : ''}
</div>`).join('')}
</div>`;
  }

  // ── Detail tab: Timeline ──────────────────────────────────────────────
  function _renderDetailTimeline(c) {
    if (!c._timeline.length) {
      return '<div style="color:#4b5563;padding:20px;font-size:12px;">No timeline entries linked to this case. Timeline entries are generated from correlated multi-stage incidents.</div>';
    }
    return `<div style="display:flex;flex-direction:column;gap:4px;">
${c._timeline.map((t, i) => `
<div style="display:flex;gap:10px;align-items:flex-start;padding:8px;background:#0d1117;border-radius:5px;border-left:3px solid ${i===0?'#ef4444':'#21262d'};">
  <div style="flex-shrink:0;font-size:10px;color:#6b7280;width:120px;font-family:monospace;">${t.timestamp ? new Date(t.timestamp).toLocaleTimeString() : '—'}</div>
  <div style="flex:1;">
    <div style="font-size:11px;font-weight:600;color:#e6edf3;">${_esc(t.detection_name||t.ruleName||t.ruleId||'Event')}</div>
    <div style="font-size:10px;color:#8b949e;margin-top:2px;">
      ${_esc(t.host||t.computer||'')}${t.user||t.User ? ' · ' + _esc(t.user||t.User) : ''}
      ${t.mitreTactic ? ' · <span style="color:#a78bfa;">' + _esc(t.mitreTactic) + '</span>' : ''}
    </div>
  </div>
</div>`).join('')}
</div>`;
  }

  // ── Detail tab: Attack Chain ──────────────────────────────────────────
  function _renderDetailChain(c) {
    const ch = c._chain;
    if (!ch) {
      return '<div style="color:#4b5563;padding:20px;font-size:12px;">No attack chain linked to this case. Chains are built when BCE v10 correlates ≥2 detections into a multi-stage incident.</div>';
    }
    const stages = ch.stages || [];
    return `
<div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:14px;margin-bottom:12px;">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap;">
    <span style="font-size:14px;font-weight:800;color:#e6edf3;">${_esc(ch.title||ch.name||'Attack Chain')}</span>
    <span style="font-size:11px;padding:2px 8px;background:${_sevColor(ch.severity)}20;color:${_sevColor(ch.severity)};border-radius:4px;font-weight:700;">${_esc((ch.severity||'').toUpperCase())}</span>
    <span style="font-size:11px;color:#8b949e;">Risk: <strong style="color:#f59e0b;">${ch.riskScore??'—'}</strong></span>
    <span style="font-size:11px;color:#8b949e;">Stages: <strong>${stages.length}</strong></span>
  </div>
  <div style="font-size:11px;color:#6b7280;margin-bottom:10px;">${_esc(ch.description||'')}</div>
  <div style="display:flex;flex-direction:column;gap:5px;">
    ${stages.map((s, i) => `
    <div style="display:flex;align-items:center;gap:8px;padding:7px 10px;background:rgba(59,130,246,0.05);border-radius:5px;border-left:3px solid ${s.inferred?'#4b5563':'#3b82f6'};">
      <span style="font-size:11px;color:#6b7280;width:18px;">${i+1}</span>
      <span style="font-size:11px;font-weight:600;color:${s.inferred?'#6b7280':'#e6edf3'};">${_esc(s.detection_name||s.ruleId||'Stage')}</span>
      <span style="font-size:9px;color:#a78bfa;background:rgba(168,85,247,0.1);padding:1px 5px;border-radius:3px;">${_esc(s.tactic||s.mitreTactic||'')}</span>
      ${s.inferred ? '<span style="font-size:9px;color:#4b5563;margin-left:auto;">⋯ inferred</span>' : '<span style="font-size:9px;color:#22c55e;margin-left:auto;">✓ observed</span>'}
    </div>`).join('')}
  </div>
</div>`;
  }

  // ── Detail tab: Notes ─────────────────────────────────────────────────
  function _renderDetailNotes(c) {
    return `
<div style="margin-bottom:12px;">
  <textarea id="caseNoteInput" style="width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e6edf3;padding:8px 12px;font-size:12px;resize:vertical;min-height:60px;box-sizing:border-box;" placeholder="Add investigation note…"></textarea>
  <button class="btn-primary" style="margin-top:6px;" onclick="window._cmAddNote('${_esc(c.id)}')"><i class="fas fa-paper-plane"></i> Add Note</button>
</div>
<div style="display:flex;flex-direction:column;gap:8px;">
${c.notes.map(n => `
<div style="background:${n.isSystem?'rgba(59,130,246,0.05)':'var(--bg-surface,#161b22)'};border:1px solid ${n.isSystem?'rgba(59,130,246,0.15)':'var(--border,#21262d)'};border-radius:8px;padding:10px;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;">
    <div style="width:22px;height:22px;background:${n.isSystem?'linear-gradient(135deg,#3b82f6,#1d4ed8)':'linear-gradient(135deg,#3b82f6,#a855f7)'};border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:800;color:white;flex-shrink:0;">${n.isSystem?'🤖':(n.user||'?').split(' ').map(w=>w[0]||'').join('')}</div>
    <span style="font-size:11px;font-weight:700;">${_esc(n.user)}</span>
    <span style="font-size:10px;color:#6b7280;">${n.time ? (typeof n.time === 'string' && n.time.includes('T') ? _ago(n.time) : n.time) : ''}</span>
    ${n.isSystem?'<span style="font-size:9px;padding:1px 5px;background:rgba(59,130,246,0.15);color:#60a5fa;border-radius:3px;">SYSTEM</span>':''}
  </div>
  <p style="font-size:12px;color:var(--text-secondary,#8b949e);line-height:1.5;margin:0;">${_esc(n.text)}</p>
</div>`).join('')}
</div>`;
  }

  // ══════════════════════════════════════════════════════════════════════
  //  GLOBAL WINDOW ACTIONS (called from onclick= attributes)
  // ══════════════════════════════════════════════════════════════════════

  window._cmApplyFilter = () => {
    _filterSev    = document.getElementById('cm-sev-filter')?.value    || '';
    _filterStatus = document.getElementById('cm-status-filter')?.value || '';
    renderCaseManagement();
  };

  window._cmOpenDetail = id => _openCaseDetail(id);

  window._cmAddNote = id => {
    const input = document.getElementById('caseNoteInput');
    const text  = input?.value?.trim();
    if (!text) { if (typeof showToast === 'function') showToast('Note is empty', 'warning'); return; }
    CaseMgr.addNote(id, text, _currentUser());
    input.value = '';
    if (typeof showToast === 'function') showToast('Note added', 'success');
    _openCaseDetail(id);   // re-render modal
  };

  window._cmEscalate = id => {
    CaseMgr.updateStatus(id, 'Escalated');
    CaseMgr.addNote(id, `Case escalated by ${_currentUser()}.`, _currentUser());
    if (typeof showToast === 'function') showToast(`Case ${id} escalated`, 'warning');
    renderCaseManagement();
    if (_currentCaseId === id) _openCaseDetail(id);
  };

  window._cmInProgress = id => {
    CaseMgr.updateStatus(id, 'In Progress');
    CaseMgr.addNote(id, `Investigation started by ${_currentUser()}.`, _currentUser());
    if (typeof showToast === 'function') showToast(`Case ${id} → In Progress`, 'info');
    renderCaseManagement();
    if (_currentCaseId === id) _openCaseDetail(id);
  };

  window._cmResolve = id => {
    CaseMgr.updateStatus(id, 'Resolved');
    if (typeof showToast === 'function') showToast(`Case ${id} resolved`, 'success');
    renderCaseManagement();
    if (_currentCaseId === id) _openCaseDetail(id);
  };

  window._cmReassign = id => {
    const name = prompt('Reassign to (analyst name):');
    if (!name) return;
    CaseMgr.updateAssignee(id, name.trim());
    CaseMgr.addNote(id, `Reassigned to ${name.trim()} by ${_currentUser()}.`, _currentUser());
    if (typeof showToast === 'function') showToast(`Case ${id} assigned to ${name.trim()}`, 'info');
    renderCaseManagement();
    if (_currentCaseId === id) _openCaseDetail(id);
  };

  window._cmViewInRAYKAN = incidentId => {
    if (typeof closeDetailModal === 'function') closeDetailModal();
    if (typeof navigateTo === 'function') navigateTo('raykan');
    if (typeof showToast === 'function') showToast(`Navigating to RAYKAN — Incident ${incidentId.slice(0,14)}…`, 'info');
    // After RAYKAN renders, switch to the incidents tab and highlight
    setTimeout(() => {
      if (window.RAYKAN_UI && typeof RAYKAN_UI._setTab === 'function') {
        RAYKAN_UI._setTab('incidents');
      }
    }, 600);
  };

  window._cmOpenNewCase = () => {
    const modal = document.createElement('div');
    modal.id = 'cmNewCaseOverlay';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center;';
    modal.innerHTML = `
<div style="background:#0d1117;border:1px solid #30363d;border-radius:12px;padding:24px;width:480px;max-width:90vw;max-height:80vh;overflow-y:auto;">
  <div style="font-size:16px;font-weight:800;margin-bottom:16px;color:#e6edf3;">📁 Create New Case</div>
  <div style="display:flex;flex-direction:column;gap:10px;">
    <div><label style="font-size:11px;color:#8b949e;font-weight:600;display:block;margin-bottom:4px;">Title *</label>
      <input id="cmn_title" style="width:100%;background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:7px 10px;border-radius:6px;font-size:13px;box-sizing:border-box;" placeholder="Brief case title…" /></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
      <div><label style="font-size:11px;color:#8b949e;font-weight:600;display:block;margin-bottom:4px;">Severity</label>
        <select id="cmn_sev" style="width:100%;background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:7px 10px;border-radius:6px;font-size:12px;">
          <option>CRITICAL</option><option>HIGH</option><option selected>MEDIUM</option><option>LOW</option>
        </select></div>
      <div><label style="font-size:11px;color:#8b949e;font-weight:600;display:block;margin-bottom:4px;">Assignee</label>
        <input id="cmn_assign" value="${_esc(_currentUser())}" style="width:100%;background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:7px 10px;border-radius:6px;font-size:12px;box-sizing:border-box;" /></div>
    </div>
    <div><label style="font-size:11px;color:#8b949e;font-weight:600;display:block;margin-bottom:4px;">Tags (comma separated)</label>
      <input id="cmn_tags" style="width:100%;background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:7px 10px;border-radius:6px;font-size:12px;box-sizing:border-box;" placeholder="mitre-t1059, lateral-movement, urgent" /></div>
    <div><label style="font-size:11px;color:#8b949e;font-weight:600;display:block;margin-bottom:4px;">Initial Note</label>
      <textarea id="cmn_note" style="width:100%;background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:7px 10px;border-radius:6px;font-size:12px;min-height:70px;resize:vertical;box-sizing:border-box;" placeholder="Initial investigation notes…"></textarea></div>
  </div>
  <div style="display:flex;gap:8px;margin-top:16px;">
    <button class="btn-primary" onclick="window._cmSubmitNewCase()"><i class="fas fa-folder-plus"></i> Create Case</button>
    <button onclick="document.getElementById('cmNewCaseOverlay').remove()" style="padding:7px 14px;background:transparent;border:1px solid #30363d;border-radius:6px;color:#8b949e;cursor:pointer;font-size:12px;">Cancel</button>
  </div>
</div>`;
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    document.body.appendChild(modal);
    document.getElementById('cmn_title')?.focus();
  };

  window._cmSubmitNewCase = () => {
    const title    = document.getElementById('cmn_title')?.value?.trim();
    const severity = document.getElementById('cmn_sev')?.value || 'MEDIUM';
    const assignee = document.getElementById('cmn_assign')?.value?.trim() || _currentUser();
    const tagsStr  = document.getElementById('cmn_tags')?.value?.trim();
    const note     = document.getElementById('cmn_note')?.value?.trim();
    if (!title) { if (typeof showToast==='function') showToast('Title is required', 'error'); return; }

    const now    = Date.now();
    const tags   = tagsStr ? tagsStr.split(',').map(t => t.trim()).filter(Boolean) : [];
    const notes  = [];
    if (note) notes.push({ user: assignee, time: new Date().toISOString(), isSystem: false, text: note });
    notes.push({ user: 'SOC Analyst', time: new Date().toISOString(), isSystem: true, text: `Manual case created by ${_currentUser()}.` });

    const c = {
      id: _caseId(), uuid: _uid(), title, severity: _normSev(severity), status: 'Open',
      assignee, createdAt: now, updatedAt: now, sla: _slaLabel(now, severity),
      tags, notes,
      incidentId: null, incidentSummary: null, detectionIds: [], timelineIds: [], chainId: null,
      _detections: [], _timeline: [], _chain: null, _rawEvents: [], _assets: [], _mitreTags: [],
      aceScore: null, riskScore: null, confidence: '—', behavior: '—', alertCount: 0,
      phaseChain: [], source: 'manual', sessionId: null,
    };
    _STORE.unshift(c);
    document.getElementById('cmNewCaseOverlay')?.remove();
    if (typeof showToast === 'function') showToast(`✅ Case "${c.id}" created`, 'success');
    renderCaseManagement();
  };

  window._cmExport = () => {
    const json = CaseMgr.exportJSON();
    const blob = new Blob([json], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `cases_${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    if (typeof showToast === 'function') showToast('Cases exported as JSON', 'success');
  };

  window._cmExportCase = id => {
    const c = CaseMgr.findById(id);
    if (!c) return;
    const json = JSON.stringify(c, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${c.id}_${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    if (typeof showToast === 'function') showToast(`Case ${c.id} exported`, 'success');
  };

  // ══════════════════════════════════════════════════════════════════════
  //  GLOBAL BRIDGE FUNCTIONS
  //  Called by live-detections-soc.js, raykan.js incident cards, etc.
  // ══════════════════════════════════════════════════════════════════════

  /**
   * Called by window._dsocCreateCase() in live-detections-soc.js
   * det: a row from DetectSOC.data (SOC finding / alert row)
   */
  window.createCaseFromFinding = function (det) {
    const c = CaseMgr.createFromFinding(det);
    if (!c) return;
    if (typeof showToast === 'function') showToast(`📁 Case ${c.id} created — "${c.title.slice(0,40)}"`, 'success');
    if (typeof navigateTo === 'function') navigateTo('case-management');
  };

  /**
   * Called from RAYKAN incident card "Create Case" button
   * inc: incidentSummary object from S.incidents
   */
  window.createCaseFromIncident = function (inc, result) {
    const r = result || (window.RAYKAN_UI ? window.RAYKAN_UI.getState() : null);
    const c = CaseMgr.createFromIncident(inc, r);
    if (!c) return;
    if (typeof showToast === 'function') showToast(`📁 Case ${c.id} — linked to incident ${(inc.id||'').slice(0,12)}`, 'success');
    if (typeof navigateTo === 'function') navigateTo('case-management');
  };

  /**
   * Called from RAYKAN detection card "Create Case" button
   * det: a detection object from S.detections
   */
  window.createCaseFromDetection = function (det) {
    const c = CaseMgr.createFromFinding(det);
    if (!c) return;
    if (typeof showToast === 'function') showToast(`📁 Case ${c.id} created from detection ${det.ruleId||det.id||''}`, 'success');
    if (typeof navigateTo === 'function') navigateTo('case-management');
  };

  // ══════════════════════════════════════════════════════════════════════
  //  RAYKAN PIPELINE HOOK  (FIX v20)
  //
  //  ROOT CAUSE (previous broken strategy):
  //    _gesIngestResult() is a JavaScript closure inside raykan.js IIFE.
  //    Wrapping window.RAYKAN_UI.gesIngest from outside has ZERO effect
  //    because every internal call goes directly to the closure, never
  //    through the RAYKAN_UI.gesIngest property reference.
  //
  //  CORRECT STRATEGY (v20):
  //    The real hook lives INSIDE raykan.js _gesIngestResult():
  //      if (typeof window.CaseMgr !== 'undefined')
  //        window.CaseMgr.ingestFromRAYKAN(r);
  //    That call fires on EVERY analysis path (demo, upload, batch).
  //
  //  This function's only remaining job is to log readiness confirmation
  //  once RAYKAN_UI is available and to wire openDetailModal for the
  //  case detail modal.
  // ══════════════════════════════════════════════════════════════════════

  function _installRAYKANHook() {
    if (!window.RAYKAN_UI) {
      setTimeout(_installRAYKANHook, 200);
      return;
    }
    // Hook is already inside _gesIngestResult in raykan.js (FIX v20).
    // Nothing more to wrap here.
    console.info('[CaseWiring v20] ✅ RAYKAN pipeline hook active — ' +
      'CaseMgr.ingestFromRAYKAN() fires inside _gesIngestResult on every analysis path.');
  }

  // ══════════════════════════════════════════════════════════════════════
  //  OVERRIDE renderCaseManagement
  //  Replaces the stub in advanced.js and the API version in live-pages.js.
  //  case-wiring.js loads AFTER both, so this assignment wins permanently.
  // ══════════════════════════════════════════════════════════════════════
  window.renderCaseManagement = renderCaseManagement;

  // Also override openCaseDetail and addCaseNote used by legacy callers
  window.openCaseDetail = _openCaseDetail;
  window.addCaseNote    = (id, _unused) => window._cmAddNote(id);

  // ── Expose CaseMgr publicly ────────────────────────────────────────────
  window.CaseMgr = CaseMgr;

  // ── Expose render alias (used by live-pages.js delegation guard) ───────
  window._cmRender = renderCaseManagement;

  // ── Boot ──────────────────────────────────────────────────────────────
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _installRAYKANHook);
  } else {
    // DOM already ready — poll for RAYKAN_UI asynchronously
    _installRAYKANHook();
  }

  console.info('[CaseWiring v20] ✅ Loaded — CaseMgr ready, renderCaseManagement overridden, ' +
    'openDetailModal wired, bridges installed.');

})(window);
