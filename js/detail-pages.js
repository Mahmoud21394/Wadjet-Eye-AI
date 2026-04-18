/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Dynamic Detail Pages v2.0
 *  js/detail-pages.js
 *
 *  Provides full-screen detail views for:
 *   - Campaign detail   (from /api/cti/campaigns/:id)
 *   - Finding/Alert detail (from /api/alerts/:id)
 *   - Live Detection detail (from /api/detections/:id)
 *   - IOC detail        (from /api/iocs/:id)
 *   - CVE/Vulnerability (from /api/vulnerabilities/:id)
 *   - Case detail       (from /api/cases/:id)
 *   - Threat Actor      (from /api/cti/actors/:id)
 *
 *  Each detail view includes:
 *   - Full metadata panel
 *   - Timeline of related events
 *   - Linked IOCs
 *   - MITRE ATT&CK technique mapping
 *   - "Search in AI" placeholder button
 *   - PDF export link
 * ══════════════════════════════════════════════════════════
 */
'use strict';

/* ─────────────────────────────────────────────
   DETAIL MODAL RENDERER
───────────────────────────────────────────── */

/** Show a fullscreen detail modal */
function showDetailModal(html, title = 'Detail') {
  let modal = document.getElementById('dpDetailModal');

  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'dpDetailModal';
    modal.style.cssText = `
      position:fixed;top:0;left:0;right:0;bottom:0;
      background:rgba(0,0,0,.9);z-index:9998;
      display:flex;align-items:flex-start;justify-content:center;
      overflow-y:auto;padding:20px;
    `;
    modal.onclick = (e) => { if (e.target === modal) closeDpModal(); };
    document.body.appendChild(modal);
  }

  modal.innerHTML = `
    <div style="background:#161b22;border:1px solid #30363d;border-radius:16px;
      width:100%;max-width:900px;min-height:400px;margin:auto;overflow:hidden">
      <!-- Modal Header -->
      <div style="background:#21262d;padding:14px 20px;display:flex;align-items:center;justify-content:space-between;
        border-bottom:1px solid #30363d">
        <div style="font-size:1em;font-weight:700;color:#e6edf3">
          <i class="fas fa-file-alt" style="color:#3b82f6;margin-right:8px"></i>${title}
        </div>
        <button onclick="closeDpModal()"
          style="background:#ef444422;border:1px solid #ef444444;color:#ef4444;
            border-radius:6px;padding:4px 12px;cursor:pointer;font-size:.85em">
          ✕ Close
        </button>
      </div>
      <!-- Body -->
      <div style="padding:24px">${html}</div>
    </div>
  `;

  modal.style.display = 'flex';
  document.body.style.overflow = 'hidden';
}

function closeDpModal() {
  const modal = document.getElementById('dpDetailModal');
  if (modal) {
    modal.style.display = 'none';
    document.body.style.overflow = '';
  }
}

/* ─────────────────────────────────────────────
   ALERT / FINDING DETAIL
───────────────────────────────────────────── */
async function showAlertDetail(alertId) {
  showDetailModal(_loadingHTML('Loading alert…'), 'Alert Detail');

  try {
    const data = await API.alerts.get(alertId);
    if (!data) throw new Error('Alert not found');

    const sevColor = _sevC(data.severity);

    showDetailModal(`
      ${_metaHeader({
        icon:    '🚨',
        title:   data.title || 'Unknown Alert',
        badge:   `<span style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}44;padding:3px 10px;border-radius:8px;font-size:.75em;font-weight:700">${data.severity || '—'}</span>`,
        subtitle:`Status: ${data.status || '—'} · Source: ${data.source || '—'} · ${_ago(data.created_at)}`,
      })}

      ${_grid2([
        { label:'Alert ID',    value: data.id },
        { label:'Severity',    value: data.severity },
        { label:'Status',      value: data.status },
        { label:'Source',      value: data.source || '—' },
        { label:'IOC Value',   value: data.ioc_value ? `<code style="color:#58a6ff">${data.ioc_value}</code>` : '—' },
        { label:'IOC Type',    value: data.ioc_type || '—' },
        { label:'Assigned To', value: data.assigned_to || 'Unassigned' },
        { label:'Created',     value: data.created_at ? new Date(data.created_at).toLocaleString() : '—' },
      ])}

      ${data.description ? `
        <div style="background:#21262d;border-radius:8px;padding:14px;margin:16px 0">
          <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:6px">Description</div>
          <div style="font-size:.88em;color:#e6edf3;line-height:1.6">${data.description}</div>
        </div>` : ''}

      ${data.mitre_technique ? `
        <div style="margin:16px 0">
          <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:8px">MITRE ATT&CK</div>
          ${_mitreBadge(data.mitre_technique, data.mitre_tactic)}
        </div>` : ''}

      ${_aiSearchButton(`Alert: ${data.title} | IOC: ${data.ioc_value} | Severity: ${data.severity}`)}
      ${_actionButtons({
        showCase:  true,
        showHunt:  true,
        showEnrich: !!data.ioc_value,
        ioc:       data.ioc_value,
        iocType:   data.ioc_type,
      })}
    `, `Alert: ${(data.title || '').slice(0, 60)}`);

  } catch (err) {
    showDetailModal(_errorHTML(err.message), 'Error');
  }
}

/* ─────────────────────────────────────────────
   CAMPAIGN DETAIL
───────────────────────────────────────────── */
async function showCampaignDetail(campaignId) {
  showDetailModal(_loadingHTML('Loading campaign…'), 'Campaign Detail');

  try {
    const data = await API.cti.campaigns.get(campaignId);
    if (!data) throw new Error('Campaign not found');

    showDetailModal(`
      ${_metaHeader({
        icon:    '🎯',
        title:   data.name || data.title || 'Unknown Campaign',
        badge:   `<span style="background:#3b82f622;color:#3b82f6;border:1px solid #3b82f644;padding:3px 10px;border-radius:8px;font-size:.75em;font-weight:700">${data.status || 'Active'}</span>`,
        subtitle:`Threat Group: ${data.threat_actor || '—'} · First Seen: ${data.first_seen ? new Date(data.first_seen).toLocaleDateString() : '—'}`,
      })}

      ${_grid2([
        { label:'Campaign ID',    value: data.id },
        { label:'Status',         value: data.status || 'Active' },
        { label:'Threat Actor',   value: data.threat_actor || '—' },
        { label:'Target Sectors', value: (data.target_sectors || data.targets || []).join(', ') || '—' },
        { label:'Countries',      value: (data.targeted_countries || []).join(', ') || '—' },
        { label:'IOC Count',      value: data.ioc_count || '—' },
        { label:'First Seen',     value: data.first_seen ? new Date(data.first_seen).toLocaleDateString() : '—' },
        { label:'Last Activity',  value: data.last_seen  ? new Date(data.last_seen).toLocaleDateString()  : '—' },
      ])}

      ${data.description ? `
        <div style="background:#21262d;border-radius:8px;padding:14px;margin:16px 0">
          <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:6px">Campaign Summary</div>
          <div style="font-size:.88em;color:#e6edf3;line-height:1.6">${data.description}</div>
        </div>` : ''}

      ${(data.mitre_techniques || data.techniques || []).length > 0 ? `
        <div style="margin:16px 0">
          <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:8px">MITRE ATT&CK Techniques</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">
            ${(data.mitre_techniques || data.techniques || []).map(t => `
              <a href="https://attack.mitre.org/techniques/${t}/" target="_blank"
                style="background:#3b82f622;color:#3b82f6;border:1px solid #3b82f644;padding:4px 10px;
                       border-radius:6px;font-size:.75em;font-weight:600;text-decoration:none">${t}</a>
            `).join('')}
          </div>
        </div>` : ''}

      ${_aiSearchButton(`Campaign: ${data.name || data.title} | Actor: ${data.threat_actor}`)}
      ${_actionButtons({ showCase: true, showHunt: true })}
    `, `Campaign: ${(data.name || data.title || '').slice(0, 60)}`);

  } catch (err) {
    showDetailModal(_errorHTML(err.message), 'Error');
  }
}

/* ─────────────────────────────────────────────
   IOC DETAIL
───────────────────────────────────────────── */
async function showIOCDetail(iocId) {
  showDetailModal(_loadingHTML('Loading IOC…'), 'IOC Detail');

  try {
    const data = await API.iocs.get(iocId);
    if (!data) throw new Error('IOC not found');

    const riskColor = data.risk_score >= 70 ? '#ef4444'
                    : data.risk_score >= 40 ? '#f97316'
                    : data.risk_score >= 20 ? '#eab308' : '#22c55e';

    const repColor = data.reputation === 'malicious' ? '#ef4444'
                   : data.reputation === 'suspicious' ? '#f97316' : '#22c55e';

    showDetailModal(`
      ${_metaHeader({
        icon:    '🔗',
        title:   data.value || 'Unknown IOC',
        badge:   `<span style="background:${repColor}22;color:${repColor};border:1px solid ${repColor}44;padding:3px 10px;border-radius:8px;font-size:.75em;font-weight:700;text-transform:uppercase">${data.reputation || 'unknown'}</span>`,
        subtitle:`Type: ${data.type} · Risk Score: ${data.risk_score || 0}/100 · Source: ${data.feed_source || data.source || '—'}`,
      })}

      <!-- Risk gauge -->
      <div style="background:#21262d;border-radius:8px;padding:14px;margin-bottom:16px">
        <div style="display:flex;justify-content:space-between;margin-bottom:6px">
          <span style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase">Risk Score</span>
          <span style="font-size:.9em;font-weight:800;color:${riskColor}">${data.risk_score || 0}/100</span>
        </div>
        <div style="background:#161b22;border-radius:4px;height:8px;overflow:hidden">
          <div style="height:100%;width:${data.risk_score||0}%;background:${riskColor};border-radius:4px;transition:width .4s"></div>
        </div>
      </div>

      ${_grid2([
        { label:'IOC Value',    value: `<code style="color:#58a6ff;word-break:break-all">${data.value}</code>` },
        { label:'Type',         value: data.type },
        { label:'Reputation',   value: data.reputation || '—' },
        { label:'Confidence',   value: data.confidence ? `${data.confidence}%` : '—' },
        { label:'Source',       value: data.feed_source || data.source || '—' },
        { label:'Country',      value: data.country || '—' },
        { label:'Threat Actor', value: data.threat_actor || '—' },
        { label:'Last Seen',    value: data.last_seen ? new Date(data.last_seen).toLocaleString() : '—' },
      ])}

      ${(data.tags || []).length > 0 ? `
        <div style="margin:12px 0">
          <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:6px">Tags</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">
            ${(data.tags || []).map(t => `
              <span style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:3px 8px;border-radius:6px;font-size:.75em">${t}</span>
            `).join('')}
          </div>
        </div>` : ''}

      <!-- External links -->
      <div style="margin:16px 0">
        <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:8px">External Intelligence</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          ${data.type === 'ip' || data.type === 'domain' || data.type === 'url' ? `
            <a href="https://www.virustotal.com/gui/search/${encodeURIComponent(data.value)}" target="_blank"
              style="background:#21262d;border:1px solid #30363d;color:#8b949e;padding:6px 12px;border-radius:8px;font-size:.8em;text-decoration:none">
              🦠 VirusTotal
            </a>` : ''}
          ${data.type === 'ip' ? `
            <a href="https://www.abuseipdb.com/check/${encodeURIComponent(data.value)}" target="_blank"
              style="background:#21262d;border:1px solid #30363d;color:#8b949e;padding:6px 12px;border-radius:8px;font-size:.8em;text-decoration:none">
              🚨 AbuseIPDB
            </a>
            <a href="https://otx.alienvault.com/browse/global/indicators/IPv4/${encodeURIComponent(data.value)}" target="_blank"
              style="background:#21262d;border:1px solid #30363d;color:#8b949e;padding:6px 12px;border-radius:8px;font-size:.8em;text-decoration:none">
              👁 AlienVault OTX
            </a>` : ''}
          ${data.type === 'cve' ? `
            <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(data.value.toUpperCase())}" target="_blank"
              style="background:#21262d;border:1px solid #30363d;color:#8b949e;padding:6px 12px;border-radius:8px;font-size:.8em;text-decoration:none">
              📋 NVD Detail
            </a>` : ''}
        </div>
      </div>

      ${_aiSearchButton(`IOC: ${data.value} | Type: ${data.type} | Reputation: ${data.reputation}`)}
      ${_actionButtons({ showCase: true, showEnrich: true, ioc: data.value, iocType: data.type })}
    `, `IOC: ${(data.value || '').slice(0, 60)}`);

  } catch (err) {
    showDetailModal(_errorHTML(err.message), 'Error');
  }
}

/* ─────────────────────────────────────────────
   CVE / VULNERABILITY DETAIL
───────────────────────────────────────────── */
async function showCVEDetail(cveId) {
  showDetailModal(_loadingHTML(`Loading ${cveId}…`), 'CVE Detail');

  try {
    const data = await API.vulns.get(cveId);
    if (!data) throw new Error(`CVE ${cveId} not found`);

    const sevColor = data.severity === 'CRITICAL' ? '#ef4444'
                   : data.severity === 'HIGH'     ? '#f97316'
                   : data.severity === 'MEDIUM'   ? '#eab308' : '#22c55e';

    const scoreDisplay = data.cvss_v3_score != null
      ? `<span style="font-size:2em;font-weight:900;color:${sevColor}">${data.cvss_v3_score}</span><span style="color:#8b949e;font-size:.85em"> CVSS v3</span>`
      : '—';

    showDetailModal(`
      ${_metaHeader({
        icon:    '⚠️',
        title:   data.cve_id || cveId,
        badge:   `<span style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}44;padding:3px 10px;border-radius:8px;font-size:.75em;font-weight:700">${data.severity || '—'}</span>
          ${data.in_cisa_kev ? '<span style="background:#dc262622;color:#dc2626;border:1px solid #dc262644;padding:3px 10px;border-radius:8px;font-size:.75em;font-weight:700;margin-left:6px">CISA KEV</span>' : ''}
          ${data.exploited   ? '<span style="background:#ef444422;color:#ef4444;border:1px solid #ef444444;padding:3px 10px;border-radius:8px;font-size:.75em;font-weight:700;margin-left:6px">EXPLOITED</span>' : ''}`,
        subtitle:`CVSS: ${data.cvss_v3_score || '—'} · Published: ${data.published_at || '—'} · Source: ${data.source || 'NVD'}`,
      })}

      <div style="display:flex;gap:20px;align-items:flex-start;margin-bottom:16px;flex-wrap:wrap">
        <!-- Score card -->
        <div style="background:#21262d;border-radius:10px;padding:16px 20px;text-align:center;min-width:100px">
          ${scoreDisplay}
          <div style="font-size:.65em;color:#8b949e;text-transform:uppercase;margin-top:4px">CVSS Score</div>
        </div>
        <!-- Vector -->
        ${data.cvss_vector ? `
        <div style="background:#21262d;border-radius:10px;padding:16px">
          <div style="font-size:.65em;color:#8b949e;text-transform:uppercase;margin-bottom:6px">Attack Vector</div>
          <code style="font-size:.75em;color:#58a6ff;word-break:break-all">${data.cvss_vector}</code>
        </div>` : ''}
      </div>

      ${data.description ? `
        <div style="background:#21262d;border-radius:8px;padding:14px;margin-bottom:16px">
          <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:6px">Description</div>
          <div style="font-size:.88em;color:#e6edf3;line-height:1.6">${data.description}</div>
        </div>` : ''}

      ${_grid2([
        { label:'Attack Vector',      value: data.attack_vector || '—' },
        { label:'Attack Complexity',  value: data.attack_complexity || '—' },
        { label:'Privileges Required',value: data.privileges_required || '—' },
        { label:'User Interaction',   value: data.user_interaction || '—' },
        { label:'Published',          value: data.published_at || '—' },
        { label:'Modified',           value: data.modified_at  || '—' },
        { label:'CISA KEV',           value: data.in_cisa_kev ? '✓ Yes — Actively Exploited' : 'No' },
        { label:'Remediation Due',    value: data.cisa_remediation_due || '—' },
      ])}

      ${(data.affected_products || []).length > 0 ? `
        <div style="margin:12px 0">
          <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:6px">Affected Products (top 5)</div>
          ${(data.affected_products || []).slice(0, 5).map(p => `
            <div style="background:#21262d;border-radius:6px;padding:6px 10px;margin-bottom:4px;font-size:.8em;color:#8b949e">
              <code>${typeof p === 'string' ? p : (p.cpe || JSON.stringify(p))}</code>
            </div>
          `).join('')}
        </div>` : ''}

      <!-- Links -->
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin:16px 0">
        <a href="https://nvd.nist.gov/vuln/detail/${cveId}" target="_blank"
          style="background:#21262d;border:1px solid #30363d;color:#8b949e;padding:6px 12px;border-radius:8px;font-size:.8em;text-decoration:none">
          📋 NVD Detail
        </a>
        <a href="https://www.cve.org/CVERecord?id=${cveId}" target="_blank"
          style="background:#21262d;border:1px solid #30363d;color:#8b949e;padding:6px 12px;border-radius:8px;font-size:.8em;text-decoration:none">
          🔗 CVE.org
        </a>
        ${data.in_cisa_kev ? `
        <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank"
          style="background:#dc262622;border:1px solid #dc262644;color:#dc2626;padding:6px 12px;border-radius:8px;font-size:.8em;text-decoration:none">
          🚨 CISA KEV Entry
        </a>` : ''}
      </div>

      ${_aiSearchButton(`CVE: ${cveId} | Severity: ${data.severity} | CVSS: ${data.cvss_v3_score}`)}
    `, `CVE: ${cveId}`);

  } catch (err) {
    showDetailModal(_errorHTML(err.message), 'Error');
  }
}

/* ─────────────────────────────────────────────
   CASE DETAIL
───────────────────────────────────────────── */
async function showCaseDetail(caseId) {
  showDetailModal(_loadingHTML('Loading case…'), 'Case Detail');

  try {
    const data = await API.cases.get(caseId);
    if (!data) throw new Error('Case not found');

    const sevColor = _sevC(data.severity);

    const notes    = data.notes    || [];
    const timeline = data.timeline || [];
    const iocs     = data.iocs     || [];

    showDetailModal(`
      ${_metaHeader({
        icon:    '📁',
        title:   data.title || 'Unknown Case',
        badge:   `<span style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}44;padding:3px 10px;border-radius:8px;font-size:.75em;font-weight:700">${data.severity || '—'}</span>
          <span style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:3px 10px;border-radius:8px;font-size:.75em;font-weight:700;margin-left:6px">${data.status || '—'}</span>`,
        subtitle:`Assigned: ${data.assignee?.name || data.assigned_to || 'Unassigned'} · Created: ${data.created_at ? new Date(data.created_at).toLocaleDateString() : '—'}`,
      })}

      ${_grid2([
        { label:'Case ID',       value: data.id },
        { label:'Severity',      value: data.severity || '—' },
        { label:'Status',        value: data.status   || '—' },
        { label:'Assigned To',   value: data.assignee?.name || data.assigned_to || 'Unassigned' },
        { label:'SLA Deadline',  value: data.sla_deadline ? new Date(data.sla_deadline).toLocaleString() : '—' },
        { label:'SLA Breached',  value: data.sla_breached ? '⚠️ YES' : 'No' },
        { label:'Findings',      value: data.findings_count || '—' },
        { label:'Kill Chain',    value: data.kill_chain_phase || '—' },
      ])}

      ${data.description ? `
        <div style="background:#21262d;border-radius:8px;padding:14px;margin-bottom:16px">
          <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:6px">Description</div>
          <div style="font-size:.88em;color:#e6edf3;line-height:1.6">${data.description}</div>
        </div>` : ''}

      <!-- Notes -->
      ${notes.length > 0 ? `
        <div style="margin:16px 0">
          <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:8px">
            Case Notes (${notes.length})
          </div>
          ${notes.slice(0, 5).map(n => `
            <div style="background:#21262d;border-radius:8px;padding:10px 12px;margin-bottom:8px;border-left:3px solid #3b82f6">
              <div style="font-size:.85em;color:#e6edf3;line-height:1.5">${n.content || n.note || n.text || JSON.stringify(n)}</div>
              <div style="font-size:.72em;color:#8b949e;margin-top:4px">${n.author?.name || n.created_by || '—'} · ${n.created_at ? new Date(n.created_at).toLocaleString() : ''}</div>
            </div>
          `).join('')}
        </div>` : ''}

      <!-- Linked IOCs -->
      ${iocs.length > 0 ? `
        <div style="margin:16px 0">
          <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:8px">
            Linked IOCs (${iocs.length})
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">
            ${iocs.slice(0, 10).map(ioc => `
              <code onclick="showIOCDetail('${ioc.id || ioc.ioc_id}')" style="background:#21262d;color:#58a6ff;border:1px solid #30363d;padding:4px 8px;border-radius:6px;font-size:.75em;cursor:pointer">
                ${ioc.value || ioc.ioc_value || '—'}
              </code>
            `).join('')}
          </div>
        </div>` : ''}

      <!-- Timeline -->
      ${timeline.length > 0 ? `
        <div style="margin:16px 0">
          <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:8px">Timeline (${timeline.length})</div>
          ${timeline.slice(0, 6).map(t => `
            <div style="display:flex;gap:10px;margin-bottom:10px">
              <div style="width:10px;height:10px;border-radius:50%;background:#3b82f6;margin-top:4px;flex-shrink:0"></div>
              <div>
                <div style="font-size:.82em;color:#e6edf3">${t.description || t.event || t.action || '—'}</div>
                <div style="font-size:.72em;color:#8b949e">${t.created_at ? new Date(t.created_at).toLocaleString() : ''} · ${t.created_by || '—'}</div>
              </div>
            </div>
          `).join('')}
        </div>` : ''}

      <!-- Export PDF button -->
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:16px">
        <button onclick="window.open(API.cases.exportPDF('${caseId}'), '_blank')"
          style="background:#ef444422;border:1px solid #ef444444;color:#ef4444;border-radius:8px;padding:8px 16px;cursor:pointer;font-size:.85em">
          <i class="fas fa-file-pdf"></i> Export PDF
        </button>
        ${_aiSearchButton(`Case: ${data.title}`, true)}
      </div>
    `, `Case: ${(data.title || '').slice(0, 60)}`);

  } catch (err) {
    showDetailModal(_errorHTML(err.message), 'Error');
  }
}

/* ─────────────────────────────────────────────
   THREAT ACTOR DETAIL
───────────────────────────────────────────── */
async function showActorDetail(actorId) {
  showDetailModal(_loadingHTML('Loading threat actor…'), 'Threat Actor');

  try {
    const data = await API.cti.actors.get(actorId);
    if (!data) throw new Error('Actor not found');

    const motivColor = {
      'ransomware':'#ef4444', 'espionage':'#3b82f6', 'financial':'#f97316',
      'hacktivism':'#8b5cf6', 'sabotage':'#dc2626',
    }[data.motivation?.toLowerCase()] || '#8b949e';

    showDetailModal(`
      ${_metaHeader({
        icon:    '👤',
        title:   data.name || 'Unknown Actor',
        badge:   `<span style="background:${motivColor}22;color:${motivColor};border:1px solid ${motivColor}44;padding:3px 10px;border-radius:8px;font-size:.75em;font-weight:700;text-transform:uppercase">${data.motivation || 'Unknown'}</span>`,
        subtitle:`Origin: ${data.origin_country || '—'} · Sophistication: ${data.sophistication || '—'} · First Seen: ${data.first_seen || '—'}`,
      })}

      ${_grid2([
        { label:'Actor ID',        value: data.id },
        { label:'Aliases',         value: (data.aliases || []).join(', ') || '—' },
        { label:'Origin Country',  value: data.origin_country || '—' },
        { label:'Motivation',      value: data.motivation     || '—' },
        { label:'Sophistication',  value: data.sophistication || '—' },
        { label:'Active Since',    value: data.first_seen     || '—' },
        { label:'Last Activity',   value: data.last_seen ? new Date(data.last_seen).toLocaleDateString() : '—' },
        { label:'Confidence',      value: data.confidence ? `${data.confidence}%` : '—' },
      ])}

      ${data.description ? `
        <div style="background:#21262d;border-radius:8px;padding:14px;margin-bottom:16px">
          <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:6px">Actor Profile</div>
          <div style="font-size:.88em;color:#e6edf3;line-height:1.6">${data.description}</div>
        </div>` : ''}

      ${(data.mitre_techniques || data.techniques || []).length > 0 ? `
        <div style="margin:16px 0">
          <div style="font-size:.75em;font-weight:700;color:#8b949e;text-transform:uppercase;margin-bottom:8px">
            Known MITRE Techniques (${(data.mitre_techniques || data.techniques || []).length})
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">
            ${(data.mitre_techniques || data.techniques || []).slice(0, 15).map(t => `
              <a href="https://attack.mitre.org/techniques/${t}/" target="_blank"
                style="background:#3b82f622;color:#3b82f6;border:1px solid #3b82f644;padding:4px 8px;
                       border-radius:6px;font-size:.72em;font-weight:600;text-decoration:none">${t}</a>
            `).join('')}
          </div>
        </div>` : ''}

      ${_aiSearchButton(`Threat Actor: ${data.name} | Motivation: ${data.motivation} | Country: ${data.origin_country}`)}
      ${_actionButtons({ showCase: true, showHunt: true })}
    `, `Threat Actor: ${data.name || ''}`);

  } catch (err) {
    showDetailModal(_errorHTML(err.message), 'Error');
  }
}

/* ─────────────────────────────────────────────
   UTILITY BUILDERS
───────────────────────────────────────────── */

function _sevC(sev) {
  return ({critical:'#ff4444',high:'#ff8800',medium:'#ffcc00',low:'#00cc44',info:'#4488ff'})[(sev||'').toLowerCase()] || '#8b949e';
}

function _ago(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

function _loadingHTML(msg) {
  return `<div style="text-align:center;padding:60px;color:#8b949e">
    <i class="fas fa-spinner fa-spin fa-2x"></i>
    <div style="margin-top:14px;font-size:.9em">${msg || 'Loading…'}</div>
  </div>`;
}

function _errorHTML(msg) {
  return `<div style="text-align:center;padding:40px;color:#ef4444">
    <i class="fas fa-exclamation-triangle fa-2x"></i>
    <div style="margin-top:12px;font-weight:700">Error Loading Data</div>
    <div style="margin-top:6px;font-size:.85em;color:#8b949e">${msg || 'Unknown error'}</div>
  </div>`;
}

function _metaHeader({ icon, title, badge, subtitle }) {
  return `
    <div style="margin-bottom:20px">
      <div style="display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap">
        <span style="font-size:2em">${icon}</span>
        <div style="flex:1">
          <div style="font-size:1.25em;font-weight:800;color:#e6edf3;line-height:1.3;margin-bottom:6px">${title}</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px">${badge || ''}</div>
          ${subtitle ? `<div style="font-size:.8em;color:#8b949e">${subtitle}</div>` : ''}
        </div>
      </div>
      <div style="height:1px;background:#30363d;margin-top:16px"></div>
    </div>
  `;
}

function _grid2(fields) {
  return `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:0;
      border:1px solid #30363d;border-radius:8px;overflow:hidden;margin-bottom:16px">
      ${fields.map((f, i) => `
        <div style="padding:10px 14px;${i < fields.length-1 ? 'border-bottom:1px solid #30363d;' : ''}
          ${i % 2 === 0 ? 'background:#1c2128;' : 'background:#161b22;'}">
          <div style="font-size:.7em;color:#8b949e;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-bottom:3px">${f.label}</div>
          <div style="font-size:.88em;color:#e6edf3">${f.value || '—'}</div>
        </div>
      `).join('')}
    </div>
  `;
}

function _mitreBadge(technique, tactic) {
  return `
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      ${tactic ? `<a href="https://attack.mitre.org/tactics/${tactic}/" target="_blank"
        style="background:#8b5cf622;color:#8b5cf6;border:1px solid #8b5cf644;padding:4px 10px;border-radius:6px;font-size:.75em;font-weight:600;text-decoration:none">${tactic}</a>` : ''}
      ${technique ? `<a href="https://attack.mitre.org/techniques/${technique}/" target="_blank"
        style="background:#3b82f622;color:#3b82f6;border:1px solid #3b82f644;padding:4px 10px;border-radius:6px;font-size:.75em;font-weight:600;text-decoration:none">${technique}</a>` : ''}
    </div>
  `;
}

function _aiSearchButton(context, inline = false) {
  const encodedCtx = encodeURIComponent(context || '');
  return `
    <div style="${inline ? 'display:inline-block' : 'margin:16px 0'}">
      <button onclick="if(typeof navigateTo==='function'){closeDpModal();navigateTo('ai-orchestrator');} window.dispatchEvent(new CustomEvent('ai:prefill',{detail:{context:decodeURIComponent('${encodedCtx}')}}));"
        style="background:linear-gradient(135deg,#3b82f6,#8b5cf6);border:none;color:#fff;
          border-radius:10px;padding:9px 18px;cursor:pointer;font-size:.85em;font-weight:600;
          display:inline-flex;align-items:center;gap:8px;transition:opacity .2s"
        onmouseenter="this.style.opacity='.85'"
        onmouseleave="this.style.opacity='1'">
        <i class="fas fa-robot"></i> Search in AI Orchestrator
      </button>
    </div>
  `;
}

function _actionButtons({ showCase, showHunt, showEnrich, ioc, iocType } = {}) {
  return `
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;padding-top:12px;border-top:1px solid #30363d">
      ${showCase ? `
      <button onclick="closeDpModal();if(typeof navigateTo==='function')navigateTo('case-management');"
        style="background:#21262d;border:1px solid #30363d;color:#8b949e;border-radius:8px;padding:7px 14px;cursor:pointer;font-size:.8em">
        <i class="fas fa-folder-plus"></i> Manage Cases
      </button>` : ''}
      ${showHunt ? `
      <button onclick="closeDpModal();if(typeof navigateTo==='function')navigateTo('threat-hunting');"
        style="background:#21262d;border:1px solid #30363d;color:#8b949e;border-radius:8px;padding:7px 14px;cursor:pointer;font-size:.8em">
        <i class="fas fa-crosshairs"></i> Hunt Threats
      </button>` : ''}
      ${showEnrich && ioc ? `
      <button onclick="closeDpModal();if(typeof enrichIOCLive==='function')enrichIOCLive('${ioc}','${iocType||'ip'}');"
        style="background:#22c55e22;border:1px solid #22c55e44;color:#22c55e;border-radius:8px;padding:7px 14px;cursor:pointer;font-size:.8em">
        <i class="fas fa-flask"></i> Enrich IOC
      </button>` : ''}
    </div>
  `;
}

/* ─────────────────────────────────────────────
   GLOBAL EXPORTS
───────────────────────────────────────────── */
window.showAlertDetail   = showAlertDetail;
window.showCampaignDetail= showCampaignDetail;
window.showIOCDetail     = showIOCDetail;
window.showCVEDetail     = showCVEDetail;
window.showCaseDetail    = showCaseDetail;
window.showActorDetail   = showActorDetail;
window.closeDpModal      = closeDpModal;
window.showDetailModal   = showDetailModal;
