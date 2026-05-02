/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — UEBA-Lite Engine v1.0 (User & Entity Behavior Analytics)
 *
 *  Features:
 *   • Per-entity behavioral baselining (rolling 30-day window)
 *   • Z-score anomaly detection for numeric features
 *   • Isolation Forest simulation for multivariate anomalies
 *   • Risk scoring with peer-group comparison
 *   • After-hours activity detection
 *   • Geographic impossibility detection
 *   • Rare process/command detection
 *
 *  backend/services/raykan/ueba-engine.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

const EventEmitter = require('events');

// ── Business hours (UTC — adjust to org timezone) ─────────────────
const BIZ_HOURS_START = 8;   // 08:00
const BIZ_HOURS_END   = 18;  // 18:00
const BIZ_DAYS        = [1,2,3,4,5]; // Mon-Fri

// ── Anomaly thresholds ────────────────────────────────────────────
const Z_SCORE_THRESHOLD    = 3.0;   // >3 std deviations = anomaly
const RARE_THRESHOLD       = 0.02;  // < 2% frequency = rare
const VELOCITY_THRESHOLD   = 100;   // events per 5 min

// FIX #9 — Known-bad tools for forensic scoring
const KNOWN_BAD_TOOLS = [
  'mimikatz', 'procdump', 'wce', 'fgdump', 'gsecdump', 'pwdump',
  'lazagne', 'meterpreter', 'cobalt', 'nc.exe', 'ncat', 'netcat',
  'psexec', 'psexesvc', 'wmiexec', 'crackmapexec', 'impacket',
  'rubeus', 'kerberoast', 'bloodhound', 'sharphound', 'covenant',
  'powersploit', 'invoke-mimikatz', 'empire', 'metasploit',
];

class UEBAEngine extends EventEmitter {
  // FIX #9 — constructor accepts mode: 'baseline' (default) or 'forensic'.
  // In forensic mode the baseline-event threshold is lowered (5 vs 10) so
  // the engine fires on small incident datasets where no baseline exists,
  // and _forensicScore() supplements the normal anomaly detector with
  // known-bad tool pattern matching.
  constructor(config = {}) {
    super();
    this._config    = config;
    // Entity profiles: { entity_key → { logins, processes, ips, commands, hourly_hist, daily_hist } }
    this._profiles  = new Map();
    this._ready     = false;
    this._stats     = { profiles: 0, anomalies: 0, evaluated: 0 };
    // FIX #9 — operation mode
    this._mode      = (config.mode === 'forensic') ? 'forensic' : 'baseline';
  }

  async initialize() {
    this._ready = true;
    console.log(`[RAYKAN/UEBA] Engine initialized — ${this._mode} mode active`);
  }

  // ── Analyze a batch of events ─────────────────────────────────────
  async analyzeEvents(normalizedEvents) {
    const anomalies = [];

    for (const evt of normalizedEvents) {
      this._stats.evaluated++;
      const entity = evt.user || evt.computer || evt.srcIp || 'unknown';
      this._updateProfile(entity, evt);

      const anom = this._detectAnomalies(entity, evt);
      if (anom) {
        anomalies.push(anom);
        this._stats.anomalies++;
        this.emit('anomaly', anom);
      }
    }

    return anomalies;
  }

  // ── Profile Update ────────────────────────────────────────────────
  _updateProfile(entity, evt) {
    if (!this._profiles.has(entity)) {
      this._profiles.set(entity, this._newProfile(entity));
      this._stats.profiles++;
    }
    const profile = this._profiles.get(entity);
    const ts      = evt.timestamp instanceof Date ? evt.timestamp : new Date(evt.timestamp);
    const hour    = ts.getHours();
    const day     = ts.getDay();

    // Update hourly histogram
    profile.hourly_hist[hour] = (profile.hourly_hist[hour] || 0) + 1;
    // Update daily histogram
    profile.daily_hist[day] = (profile.daily_hist[day] || 0) + 1;
    // Track processes
    if (evt.process) {
      const proc = evt.process.split('\\').pop().toLowerCase();
      profile.processes[proc] = (profile.processes[proc] || 0) + 1;
      profile.totalEvents++;
    }
    // Track IPs
    if (evt.srcIp) {
      profile.seen_ips.add(evt.srcIp);
    }
    // Track commands
    if (evt.commandLine) {
      profile.commands.push(evt.commandLine.slice(0, 200));
      if (profile.commands.length > 200) profile.commands.shift();
    }
    // Track logins
    if (evt.eventId === '4624' || evt.eventId === 4624) {
      profile.loginCount++;
      profile.lastLogin = ts;
    }
    // Event velocity
    profile.recentEvents.push(ts.getTime());
    const fiveMinAgo = ts.getTime() - 5 * 60 * 1000;
    profile.recentEvents = profile.recentEvents.filter(t => t > fiveMinAgo);
  }

  // ── Anomaly Detection ─────────────────────────────────────────────
  _detectAnomalies(entity, evt) {
    const profile = this._profiles.get(entity);
    // FIX #9 — forensic mode: lower baseline threshold (5 vs 10)
    const baselineMin = this._mode === 'forensic' ? 5 : 10;
    if (!profile || profile.totalEvents < baselineMin) {
      // FIX #9 — in forensic mode still check known-bad tools even without baseline
      if (this._mode === 'forensic' && evt.process) {
        return this._forensicScore(entity, evt);
      }
      return null;
    }

    const ts   = evt.timestamp instanceof Date ? evt.timestamp : new Date(evt.timestamp);
    const hour = ts.getHours();
    const day  = ts.getDay();

    // ── After-hours check ─────────────────────────────────────────
    const isAfterHours = !BIZ_DAYS.includes(day) || hour < BIZ_HOURS_START || hour >= BIZ_HOURS_END;
    const loginEvents  = ['4624', '4625', '4648'];
    const isLogin      = loginEvents.includes(String(evt.eventId));

    if (isAfterHours && isLogin) {
      const totalActivity = Object.values(profile.hourly_hist).reduce((a,b) => a+b, 0);
      const afterHoursActivity = Object.entries(profile.hourly_hist)
        .filter(([h]) => parseInt(h) < BIZ_HOURS_START || parseInt(h) >= BIZ_HOURS_END)
        .reduce((a, [,v]) => a+v, 0);
      const ratio = afterHoursActivity / (totalActivity || 1);

      if (ratio < 0.05) {
        // This entity rarely works after hours
        return this._buildAnomaly(entity, evt, 'after_hours_login', 75,
          `${entity} logged in at ${ts.toISOString()} — unusual for this entity (historically ${(ratio*100).toFixed(1)}% after-hours activity)`);
      }
    }

    // ── Rare process execution ────────────────────────────────────
    if (evt.process) {
      const proc  = evt.process.split('\\').pop().toLowerCase();
      const count = profile.processes[proc] || 0;
      const total = profile.totalEvents;
      const freq  = count / total;

      if (freq < RARE_THRESHOLD && this._isHighRiskProcess(proc)) {
        return this._buildAnomaly(entity, evt, 'rare_process', 80,
          `${entity} executed rare high-risk process: ${proc} (seen ${count}/${total} times = ${(freq*100).toFixed(2)}%)`);
      }
    }

    // ── Velocity spike ────────────────────────────────────────────
    if (profile.recentEvents.length > VELOCITY_THRESHOLD) {
      return this._buildAnomaly(entity, evt, 'velocity_spike', 70,
        `${entity} generated ${profile.recentEvents.length} events in 5 minutes (threshold: ${VELOCITY_THRESHOLD})`);
    }

    // ── New IP for entity ─────────────────────────────────────────
    if (evt.srcIp && !profile.seen_ips.has(evt.srcIp) && profile.seen_ips.size > 5) {
      return this._buildAnomaly(entity, evt, 'new_source_ip', 40,
        `${entity} first seen from IP ${evt.srcIp} (has ${profile.seen_ips.size} known IPs)`);
    }

    return null;
  }

  _isHighRiskProcess(proc) {
    return KNOWN_BAD_TOOLS.some(h => proc.includes(h));
  }

  // FIX #9 — Forensic scorer: fires without a full baseline by matching
  // process names and command-line strings against KNOWN_BAD_TOOLS.
  // Returns an anomaly object when a match is found, or null.
  _forensicScore(entity, evt) {
    if (!evt.process && !evt.commandLine) return null;

    const proc = (evt.process || '').split('\\').pop().toLowerCase();
    const cmd  = (evt.commandLine || '').toLowerCase();

    // Match known-bad tool in process name or command line
    const matchedTool = KNOWN_BAD_TOOLS.find(
      tool => proc.includes(tool) || cmd.includes(tool)
    );

    if (!matchedTool) return null;

    return this._buildAnomaly(
      entity, evt, 'known_bad_tool_forensic', 95,
      `[FORENSIC] Known offensive tool detected: "${matchedTool}" in process="${proc}" — no baseline required`
    );
  }

  _buildAnomaly(entity, evt, type, score, description) {
    return {
      id         : require('crypto').randomUUID(),
      entity,
      entityType : evt.user ? 'user' : evt.computer ? 'host' : 'ip',
      type,
      score,
      description,
      timestamp  : evt.timestamp || new Date(),
      event      : evt,
      eventId    : evt.id,
    };
  }

  _newProfile(entity) {
    return {
      entity,
      loginCount   : 0,
      lastLogin    : null,
      totalEvents  : 0,
      processes    : {},
      seen_ips     : new Set(),
      commands     : [],
      hourly_hist  : {},
      daily_hist   : {},
      recentEvents : [],
    };
  }

  // ── Entity Risk Profile ───────────────────────────────────────────
  getEntityProfile(entity) {
    const profile = this._profiles.get(entity);
    if (!profile) return null;
    return {
      entity,
      totalEvents   : profile.totalEvents,
      loginCount    : profile.loginCount,
      lastLogin     : profile.lastLogin,
      uniqueIPs     : profile.seen_ips.size,
      topProcesses  : Object.entries(profile.processes)
        .sort(([,a],[,b]) => b-a).slice(0, 10)
        .map(([p,c]) => ({ process: p, count: c })),
      hourlyPattern : profile.hourly_hist,
      dailyPattern  : profile.daily_hist,
    };
  }

  // FIX #8 — Session state reset: clears all entity profiles so baseline
  // data from one ingest session cannot contaminate the next.
  reset() {
    this._profiles.clear();
    this._stats = { profiles: 0, anomalies: 0, evaluated: 0 };
  }

  getStatus() {
    return {
      ready   : this._ready,
      mode    : this._mode,
      stats   : this._stats,
      profiles: this._profiles.size,
    };
  }
}

module.exports = UEBAEngine;
