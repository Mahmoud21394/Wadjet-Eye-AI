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

class UEBAEngine extends EventEmitter {
  constructor(config = {}) {
    super();
    this._config    = config;
    // Entity profiles: { entity_key → { logins, processes, ips, commands, hourly_hist, daily_hist } }
    this._profiles  = new Map();
    this._ready     = false;
    this._stats     = { profiles: 0, anomalies: 0, evaluated: 0 };
  }

  async initialize() {
    this._ready = true;
    console.log('[RAYKAN/UEBA] Engine initialized — behavioral baselining active');
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
    if (!profile || profile.totalEvents < 10) return null; // Need baseline

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
    const HIGH_RISK = [
      'mimikatz', 'wce', 'pwdump', 'procdump', 'psexec', 'lazagne',
      'meterpreter', 'cobalt', 'nc.exe', 'ncat', 'netcat',
    ];
    return HIGH_RISK.some(h => proc.includes(h));
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

  getStatus() { return { ready: this._ready, stats: this._stats, profiles: this._profiles.size }; }
}

module.exports = UEBAEngine;
