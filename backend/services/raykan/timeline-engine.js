/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Timeline & Visualization Engine v1.0
 *
 *  Builds rich, interactive forensic timelines from events + detections.
 *  Output is consumed by the React frontend for:
 *   • Chronological event timeline
 *   • Attack-path visualization (D3 force graph)
 *   • Entity relationship graph
 *   • Kill-chain overlay
 *
 *  backend/services/raykan/timeline-engine.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const crypto = require('crypto');

// ── Event type → icon + color mapping (for frontend) ─────────────
const EVENT_STYLE = {
  authentication    : { icon: 'key',          color: '#60a5fa', priority: 5 },
  process_creation  : { icon: 'terminal',     color: '#34d399', priority: 7 },
  network_connection: { icon: 'network-wired', color: '#818cf8', priority: 6 },
  file_event        : { icon: 'file-alt',     color: '#fbbf24', priority: 6 },
  registry_event    : { icon: 'server',       color: '#f87171', priority: 7 },
  detection         : { icon: 'shield-alt',   color: '#ef4444', priority: 10 },
  anomaly           : { icon: 'exclamation-triangle', color: '#f59e0b', priority: 9 },
  generic           : { icon: 'circle',       color: '#9ca3af', priority: 3 },
};

// ── Severity → color ─────────────────────────────────────────────
const SEVERITY_COLOR = {
  critical     : '#ef4444',
  high         : '#f97316',
  medium       : '#eab308',
  low          : '#22c55e',
  informational: '#6b7280',
};

class TimelineEngine {
  constructor(config = {}) {
    this._config = config;
  }

  // ── Build Full Timeline ───────────────────────────────────────────
  /**
   * Merges events and detections into a unified chronological timeline.
   * @returns {Array<TimelineEntry>}
   */
  buildTimeline(events, detections) {
    const entries = [];

    // Add raw events
    for (const evt of events) {
      entries.push(this._eventToTimeline(evt));
    }

    // Overlay detections (highlighted)
    for (const det of detections) {
      entries.push(this._detectionToTimeline(det));
    }

    // Sort by timestamp
    entries.sort((a, b) => new Date(a.ts) - new Date(b.ts));

    // Deduplicate and add sequence numbers
    return entries.map((e, i) => ({ ...e, seq: i + 1 }));
  }

  // ── Build Entity-Focused Timeline ─────────────────────────────────
  buildEntityTimeline(entityId, events) {
    const relevant = events.filter(e =>
      e.user === entityId || e.computer === entityId ||
      e.srcIp === entityId || e.process?.includes(entityId)
    );

    return relevant
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
      .map((e, i) => ({
        ...this._eventToTimeline(e),
        entityHighlight: entityId,
        seq            : i + 1,
      }));
  }

  // ── Build Attack-Graph Data (D3-compatible) ───────────────────────
  buildAttackGraph(detections, chains) {
    const nodes = new Map();
    const links = [];

    // Add entity nodes from detections
    for (const det of detections) {
      this._addNode(nodes, det.computer, 'host',    det.severity);
      this._addNode(nodes, det.user,     'user',    det.severity);
      this._addNode(nodes, det.process,  'process', det.severity);
      this._addNode(nodes, det.srcIp,    'ip',      det.severity);
      this._addNode(nodes, det.dstIp,    'ip',      det.severity);

      // Link process → host
      if (det.process && det.computer) {
        links.push(this._buildLink(det.process, det.computer, 'runs_on', det.severity));
      }
      // Link user → process
      if (det.user && det.process) {
        links.push(this._buildLink(det.user, det.process, 'executed', det.severity));
      }
      // Link host → IP (network)
      if (det.computer && det.dstIp) {
        links.push(this._buildLink(det.computer, det.dstIp, 'connected_to', det.severity));
      }
    }

    // Add chain-level links
    for (const chain of chains) {
      if (chain.type === 'lateral_movement' && chain.source && chain.target) {
        this._addNode(nodes, chain.source, 'host', chain.severity);
        this._addNode(nodes, chain.target, 'host', chain.severity);
        links.push(this._buildLink(chain.source, chain.target, 'lateral_movement', chain.severity));
      }
    }

    return {
      nodes: Array.from(nodes.values()).filter(n => n.id),
      links: this._deduplicateLinks(links),
    };
  }

  // ── Build MITRE Heat-Map Data ─────────────────────────────────────
  buildMitreHeatmap(detections) {
    const heatmap = {};
    for (const det of detections) {
      const techs = det.mitre?.techniques || [];
      for (const tech of techs) {
        if (!heatmap[tech.id]) {
          heatmap[tech.id] = {
            id    : tech.id,
            name  : tech.name,
            tactic: tech.tactic?.name,
            count : 0,
            severity: 'low',
          };
        }
        heatmap[tech.id].count++;
        heatmap[tech.id].severity = this._maxSeverity([heatmap[tech.id].severity, det.severity]);
      }
    }
    return Object.values(heatmap).sort((a,b) => b.count - a.count);
  }

  // ── Private helpers ───────────────────────────────────────────────
  _eventToTimeline(evt) {
    const type  = this._classifyType(evt);
    const style = EVENT_STYLE[type] || EVENT_STYLE.generic;

    return {
      id         : evt.id || crypto.randomUUID(),
      ts         : evt.timestamp instanceof Date ? evt.timestamp.toISOString() : new Date(evt.timestamp || Date.now()).toISOString(),
      type,
      eventId    : evt.eventId,
      title      : this._eventTitle(evt, type),
      description: this._eventDesc(evt),
      entity     : evt.computer || evt.user || evt.srcIp || 'unknown',
      user       : evt.user,
      host       : evt.computer,
      process    : evt.process,
      srcIp      : evt.srcIp,
      dstIp      : evt.dstIp,
      icon       : style.icon,
      color      : style.color,
      severity   : 'informational',
      severityColor: SEVERITY_COLOR.informational,
      priority   : style.priority,
      isDetection: false,
      raw        : evt.eventId ? { eventId: evt.eventId, channel: evt.channel } : undefined,
    };
  }

  _detectionToTimeline(det) {
    return {
      id         : det.id || crypto.randomUUID(),
      ts         : det.timestamp instanceof Date ? det.timestamp.toISOString() : new Date(det.timestamp || Date.now()).toISOString(),
      type       : 'detection',
      ruleId     : det.ruleId,
      ruleName   : det.ruleName,
      title      : `🚨 ${det.ruleName}`,
      description: det.description || `Sigma rule triggered: ${det.ruleName}`,
      entity     : det.computer || det.user || 'unknown',
      user       : det.user,
      host       : det.computer,
      process    : det.process,
      srcIp      : det.srcIp,
      dstIp      : det.dstIp,
      icon       : 'shield-alt',
      color      : SEVERITY_COLOR[det.severity] || SEVERITY_COLOR.medium,
      severity   : det.severity,
      severityColor: SEVERITY_COLOR[det.severity] || SEVERITY_COLOR.medium,
      confidence : det.confidence,
      priority   : 10,
      isDetection: true,
      mitre      : det.mitre,
      tags       : det.tags,
      ai         : det.ai,
      riskScore  : det.riskScore,
    };
  }

  _addNode(nodes, id, type, severity) {
    if (!id) return;
    const key = `${type}:${id}`;
    if (!nodes.has(key)) {
      nodes.set(key, {
        id,
        key,
        type,
        label   : this._shortLabel(id, type),
        severity: severity || 'informational',
        color   : this._nodeColor(type, severity),
        count   : 0,
      });
    }
    nodes.get(key).count++;
    const node = nodes.get(key);
    node.severity = this._maxSeverity([node.severity, severity]);
    node.color    = this._nodeColor(type, node.severity);
  }

  _buildLink(source, target, relation, severity) {
    return {
      id      : `${source}→${target}:${relation}`,
      source,
      target,
      relation,
      severity,
      color   : SEVERITY_COLOR[severity] || '#4b5563',
    };
  }

  _deduplicateLinks(links) {
    const seen = new Set();
    return links.filter(l => {
      if (seen.has(l.id)) return false;
      seen.add(l.id);
      return true;
    });
  }

  _nodeColor(type, severity) {
    if (severity === 'critical' || severity === 'high') return SEVERITY_COLOR[severity];
    const typeColors = { host: '#60a5fa', user: '#34d399', ip: '#f97316', process: '#a78bfa' };
    return typeColors[type] || '#9ca3af';
  }

  _shortLabel(id, type) {
    if (type === 'ip') return id;
    if (type === 'host') return id?.split('.')?.[0] || id;
    if (type === 'process') return id?.split('\\')?.[id.split('\\').length-1] || id;
    return id?.length > 20 ? id.slice(0, 20) + '…' : id;
  }

  _classifyType(evt) {
    // FIX #10 — Check semantic event_type / eventCategory BEFORE falling back
    // to EventID matching.  EDR-style events carry no EventID, so without this
    // block every EDR event was silently typed as 'generic', losing its icon
    // and color classification in the frontend timeline.
    const et = (evt.eventCategory || evt.event_type || evt.raw?.event_type || '').toLowerCase();
    if (et) {
      if (['web_download','file_download','initial_access'].includes(et))    return 'file_event';
      if (['process_creation','process_start'].includes(et))                 return 'process_creation';
      if (['process_access','process_inject'].includes(et))                  return 'process_creation';
      if (['network_connection','network_connect','c2_beacon'].includes(et)) return 'network_connection';
      if (['wmi_execution','wmi_event','remote_exec'].includes(et))          return 'process_creation';
      if (['file_creation','file_write','file_enum','file_enumeration'].includes(et)) return 'file_event';
      if (['dns_query','dns_response'].includes(et))                         return 'network_connection';
      if (['data_exfiltration','exfil'].includes(et))                        return 'network_connection';
      if (['registry_set','registry_create','registry_delete'].includes(et)) return 'registry_event';
      if (['logon','login','authentication','logoff'].includes(et))          return 'authentication';
    }

    // Fallback: EventID-based classification (Windows / Sysmon)
    const eid = String(evt.eventId || '');
    if (['4624','4625','4634','4647','4648','4768','4769','4771'].includes(eid)) return 'authentication';
    if (['1','4688'].includes(eid)) return 'process_creation';
    if (['3','5156','5157','5158'].includes(eid)) return 'network_connection';
    if (['11','23','4663','4660'].includes(eid)) return 'file_event';
    if (['12','13','14'].includes(eid)) return 'registry_event';
    return 'generic';
  }

  _eventTitle(evt, type) {
    const labels = {
      authentication: `Login: ${evt.user || 'unknown'} → ${evt.computer || 'unknown'}`,
      process_creation: `Process: ${evt.process?.split('\\').pop() || 'unknown'}`,
      network_connection: `Network: ${evt.computer || 'host'} → ${evt.dstIp || 'unknown'}:${evt.dstPort || ''}`,
      file_event: `File: ${evt.filePath?.split('\\').pop() || 'unknown'}`,
      registry_event: `Registry: ${evt.regKey?.slice(-60) || 'unknown'}`,
      generic: `Event ${evt.eventId || 'unknown'} on ${evt.computer || 'unknown'}`,
    };
    return labels[type] || labels.generic;
  }

  _eventDesc(evt) {
    if (evt.commandLine) return `CMD: ${evt.commandLine.slice(0, 150)}`;
    if (evt.filePath)    return `File: ${evt.filePath}`;
    if (evt.regKey)      return `Key: ${evt.regKey}`;
    return `EventID: ${evt.eventId} | Source: ${evt.source || 'unknown'}`;
  }

  _maxSeverity(severities) {
    const order = ['critical','high','medium','low','informational'];
    for (const s of order) { if (severities.includes(s)) return s; }
    return 'informational';
  }
}

module.exports = TimelineEngine;
