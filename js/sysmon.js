/**
 * ══════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Sysmon Log Analyzer v2.0
 *  js/sysmon.js
 *
 *  Full Sysmon XML log analysis module:
 *  • Drag-and-drop XML upload
 *  • Event parsing (Event IDs 1,3,7,8,10,11,12,13,15,17,18,22,25)
 *  • Suspicious pattern detection (injection, lateral movement, C2)
 *  • MITRE ATT&CK technique mapping
 *  • Interactive timeline view with anomaly highlighting
 *  • Threat score calculation
 *  • AI investigation integration
 * ══════════════════════════════════════════════════════════
 */
'use strict';

/* ─────────────────────────────────────────────
   SYSMON EVENT ID CATALOG
───────────────────────────────────────────── */
const SYSMON_EVENTS = {
  1:  { name:'Process Create',           icon:'fa-play-circle',    mitre:['T1059','T1204','T1106'] },
  2:  { name:'File Create Time Changed', icon:'fa-clock',          mitre:['T1070'] },
  3:  { name:'Network Connect',          icon:'fa-network-wired',  mitre:['T1071','T1095'] },
  4:  { name:'Sysmon State Changed',     icon:'fa-info-circle',    mitre:[] },
  5:  { name:'Process Terminate',        icon:'fa-stop-circle',    mitre:[] },
  6:  { name:'Driver Loaded',            icon:'fa-microchip',      mitre:['T1543','T1014'] },
  7:  { name:'Image Loaded (DLL)',       icon:'fa-cube',           mitre:['T1574','T1218'] },
  8:  { name:'Create Remote Thread',     icon:'fa-code-branch',    mitre:['T1055'] },
  9:  { name:'Raw Disk Access',          icon:'fa-hdd',            mitre:['T1003','T1006'] },
  10: { name:'Process Access',           icon:'fa-crosshairs',     mitre:['T1055','T1003'] },
  11: { name:'File Create',              icon:'fa-file-plus',      mitre:['T1105','T1036'] },
  12: { name:'Registry Event (Create)',  icon:'fa-database',       mitre:['T1547','T1112'] },
  13: { name:'Registry Event (Set)',     icon:'fa-edit',           mitre:['T1547','T1112'] },
  14: { name:'Registry Event (Rename)',  icon:'fa-tag',            mitre:['T1547'] },
  15: { name:'File Create Stream Hash', icon:'fa-hashtag',        mitre:['T1564'] },
  17: { name:'Pipe Created',             icon:'fa-exchange-alt',   mitre:['T1559'] },
  18: { name:'Pipe Connected',           icon:'fa-link',           mitre:['T1559'] },
  22: { name:'DNS Query',                icon:'fa-globe',          mitre:['T1071','T1568'] },
  23: { name:'File Delete Archived',     icon:'fa-trash',          mitre:['T1070'] },
  25: { name:'Process Tampering',        icon:'fa-user-secret',    mitre:['T1055'] },
  255:{ name:'Error',                    icon:'fa-exclamation',    mitre:[] },
};

/* ─────────────────────────────────────────────
   SUSPICIOUS PATTERNS → MITRE ATT&CK MAPPING
───────────────────────────────────────────── */
const SYSMON_PATTERNS = [
  // Process Injection
  { id:'PI001', name:'Process Injection via CreateRemoteThread', severity:'critical', mitre:['T1055.001'],
    match: e => e.EventID === 8,
    desc:  'CreateRemoteThread detected — common code injection technique' },
  { id:'PI002', name:'LSASS Memory Access', severity:'critical', mitre:['T1003.001'],
    match: e => e.EventID === 10 && (e.data.TargetImage||'').toLowerCase().includes('lsass'),
    desc:  'LSASS process access — possible credential dumping attempt' },

  // Lateral Movement
  { id:'LM001', name:'PsExec / Remote Service Execution', severity:'high', mitre:['T1021.002','T1569.002'],
    match: e => e.EventID === 1 && /psexec|sc\.exe|svchost/i.test(e.data.Image||'') && /\\\\/.test(e.data.CommandLine||''),
    desc:  'Remote execution via PsExec or service control — lateral movement indicator' },
  { id:'LM002', name:'WMI Remote Command Execution', severity:'high', mitre:['T1047'],
    match: e => e.EventID === 1 && /wmic\.exe|wmiprvse/i.test(e.data.Image||''),
    desc:  'WMI process spawned — possible remote command execution' },
  { id:'LM003', name:'SMB/Admin Share Access', severity:'high', mitre:['T1021.002'],
    match: e => e.EventID === 3 && (e.data.DestinationPort === '445' || e.data.DestinationPort === 445),
    desc:  'SMB connection to port 445 — potential lateral movement via admin shares' },

  // Suspicious Execution
  { id:'SE001', name:'PowerShell Encoded Command', severity:'high', mitre:['T1059.001'],
    match: e => e.EventID === 1 && /powershell/i.test(e.data.Image||'') && /-enc|-encodedcommand/i.test(e.data.CommandLine||''),
    desc:  'PowerShell with encoded command — common obfuscation technique' },
  { id:'SE002', name:'cmd.exe Spawning Suspicious Child', severity:'high', mitre:['T1059.003'],
    match: e => e.EventID === 1 && /cmd\.exe/i.test(e.data.ParentImage||'') && /net\.exe|whoami|ipconfig|systeminfo/i.test(e.data.Image||''),
    desc:  'cmd.exe spawning reconnaissance tool — possible hands-on-keyboard activity' },
  { id:'SE003', name:'Certutil Abuse (LOLBin)', severity:'high', mitre:['T1105','T1140'],
    match: e => e.EventID === 1 && /certutil/i.test(e.data.Image||''),
    desc:  'Certutil executed — frequently abused to download payloads or decode files' },
  { id:'SE004', name:'Mshta / Rundll32 Execution', severity:'high', mitre:['T1218.005','T1218.011'],
    match: e => e.EventID === 1 && /mshta\.exe|rundll32\.exe/i.test(e.data.Image||''),
    desc:  'LOLBAS execution (mshta/rundll32) — often used to bypass application whitelisting' },
  { id:'SE005', name:'Regsvr32 (Squiblydoo)', severity:'high', mitre:['T1218.010'],
    match: e => e.EventID === 1 && /regsvr32/i.test(e.data.Image||'') && /scrobj|http/i.test(e.data.CommandLine||''),
    desc:  'Regsvr32 with remote script — Squiblydoo bypass technique detected' },

  // Persistence
  { id:'PR001', name:'Registry Run Key Persistence', severity:'medium', mitre:['T1547.001'],
    match: e => (e.EventID === 12 || e.EventID === 13) && /\\Run\\|\\RunOnce\\/i.test(e.data.TargetObject||''),
    desc:  'Registry Run key modification — potential persistence mechanism' },
  { id:'PR002', name:'Scheduled Task Creation', severity:'medium', mitre:['T1053.005'],
    match: e => e.EventID === 1 && /schtasks\.exe/i.test(e.data.Image||'') && /\/create/i.test(e.data.CommandLine||''),
    desc:  'Scheduled task created — may indicate persistence setup' },
  { id:'PR003', name:'New Service Installation', severity:'medium', mitre:['T1543.003'],
    match: e => e.EventID === 1 && /sc\.exe/i.test(e.data.Image||'') && /create/i.test(e.data.CommandLine||''),
    desc:  'Service creation detected — potential persistence or privilege escalation' },

  // C2 / Exfiltration
  { id:'C2001', name:'Suspicious DNS Query', severity:'medium', mitre:['T1071.004','T1568'],
    match: e => e.EventID === 22 && /[a-z0-9]{20,}\./i.test(e.data.QueryName||''),
    desc:  'Long random DNS query — possible DGA or DNS tunneling C2' },
  { id:'C2002', name:'Outbound Connection on Unusual Port', severity:'medium', mitre:['T1571'],
    match: e => e.EventID === 3 && ![80,443,53,8080,8443,22,25,587,993,995].includes(Number(e.data.DestinationPort)) && Number(e.data.DestinationPort) > 1024,
    desc:  'Outbound connection on non-standard port — possible C2 traffic' },
  { id:'C2003', name:'Network Connection from Script Host', severity:'high', mitre:['T1071','T1059'],
    match: e => e.EventID === 3 && /wscript|cscript|powershell/i.test(e.data.Image||''),
    desc:  'Script interpreter making network connection — high-risk C2 indicator' },

  // Defense Evasion
  { id:'DE001', name:'Log Clearing / Event Log Tampering', severity:'critical', mitre:['T1070.001'],
    match: e => e.EventID === 1 && /wevtutil/i.test(e.data.Image||'') && /cl|clear-log/i.test(e.data.CommandLine||''),
    desc:  'Event log clearing attempt — active defense evasion detected' },
  { id:'DE002', name:'DLL Side-Loading', severity:'high', mitre:['T1574.002'],
    match: e => e.EventID === 7 && !(e.data.Signature) && !/\\windows\\/i.test(e.data.ImageLoaded||''),
    desc:  'Unsigned DLL loaded from non-system location — possible DLL side-loading' },
  { id:'DE003', name:'Process Hollowing', severity:'critical', mitre:['T1055.012'],
    match: e => e.EventID === 25,
    desc:  'Process tampering event — possible process hollowing or doppelgänging' },
];

/* ─────────────────────────────────────────────
   XML PARSER
───────────────────────────────────────────── */
function _parseSysmonXML(xmlString) {
  const parser = new DOMParser();
  const doc    = parser.parseFromString(xmlString, 'application/xml');
  const parseErr = doc.querySelector('parsererror');
  if (parseErr) throw new Error('Invalid XML: ' + parseErr.textContent.slice(0,120));

  const events = [];
  const eventNodes = doc.querySelectorAll('Event');

  eventNodes.forEach(ev => {
    try {
      const sys   = ev.querySelector('System');
      const evData= ev.querySelector('EventData');
      if (!sys) return;

      const eventID    = parseInt(sys.querySelector('EventID')?.textContent || '0');
      const timeGen    = sys.querySelector('TimeCreated')?.getAttribute('SystemTime') || new Date().toISOString();
      const computer   = sys.querySelector('Computer')?.textContent || 'Unknown';
      const providerGuid = sys.querySelector('Provider')?.getAttribute('Guid') || '';

      // Parse EventData fields
      const data = {};
      if (evData) {
        evData.querySelectorAll('Data').forEach(d => {
          const name  = d.getAttribute('Name') || '';
          const value = d.textContent || '';
          if (name) data[name] = value;
        });
      }

      events.push({
        EventID:   eventID,
        Time:      timeGen,
        Computer:  computer,
        RuleGroup: data.RuleName || '',
        data,
        raw: ev.outerHTML.slice(0, 500),
      });
    } catch{}
  });

  return events;
}

/* ─────────────────────────────────────────────
   ANALYSIS ENGINE
───────────────────────────────────────────── */
function _analyzeSysmonEvents(events) {
  const findings   = [];
  const timeline   = [];
  const eventStats = {};
  let threatScore  = 0;

  // Count event types
  events.forEach(e => {
    const eid = e.EventID;
    eventStats[eid] = (eventStats[eid] || 0) + 1;
  });

  // Run pattern matching
  events.forEach(e => {
    SYSMON_PATTERNS.forEach(pattern => {
      try {
        if (pattern.match(e)) {
          const sev    = pattern.severity;
          const points = sev==='critical'?25:sev==='high'?15:sev==='medium'?7:3;
          threatScore  += points;

          findings.push({
            id:          `${pattern.id}-${e.Time}-${Math.random().toString(36).slice(2,6)}`,
            patternId:   pattern.id,
            patternName: pattern.name,
            severity:    sev,
            desc:        pattern.desc,
            mitre:       pattern.mitre,
            event:       e,
            time:        e.Time,
            computer:    e.Computer,
            image:       e.data.Image || e.data.TargetImage || '—',
            cmdLine:     e.data.CommandLine || '—',
          });

          timeline.push({
            time:     e.Time,
            type:     'alert',
            severity: sev,
            text:     pattern.name,
            mitre:    pattern.mitre,
            detail:   e.data.Image || e.data.CommandLine || e.data.QueryName || '—',
          });
        }
      } catch {}
    });

    // Add all events to timeline (for full view)
    const evDef = SYSMON_EVENTS[e.EventID] || SYSMON_EVENTS[255];
    timeline.push({
      time:     e.Time,
      type:     'event',
      severity: 'info',
      text:     evDef.name,
      detail:   e.data.Image || e.data.CommandLine || e.data.QueryName || e.data.TargetObject || '—',
      mitre:    evDef.mitre,
      eventID:  e.EventID,
    });
  });

  // Sort timeline
  timeline.sort((a,b) => new Date(a.time) - new Date(b.time));

  // Cap score at 100
  threatScore = Math.min(100, threatScore);

  return { findings, timeline, eventStats, threatScore };
}

/* ─────────────────────────────────────────────
   RENDER SYSMON ANALYZER
───────────────────────────────────────────── */
function renderSysmonAnalyzer() {
  const wrap = document.getElementById('sysmonWrap');
  if (!wrap) return;

  wrap.innerHTML = `
  <div style="max-width:900px;margin:0 auto">
    <!-- Header -->
    <div style="margin-bottom:20px">
      <h2 style="font-size:1.1em;font-weight:800;color:#e6edf3;margin-bottom:4px">
        <i class="fas fa-file-code" style="color:#c9a227;margin-right:8px"></i>Sysmon Log Analyzer
      </h2>
      <p style="font-size:.8em;color:#8b949e">
        Upload Sysmon XML logs for automated threat analysis, MITRE ATT&CK mapping, and threat scoring.
      </p>
    </div>

    <!-- Upload Zone -->
    <div id="sysmonUploadZone" class="sysmon-upload-zone" onclick="document.getElementById('sysmonFileInput').click()" 
      ondragover="event.preventDefault();this.classList.add('drag-over')"
      ondragleave="this.classList.remove('drag-over')"
      ondrop="_sysmonDrop(event)">
      <div class="sysmon-upload-icon"><i class="fas fa-cloud-upload-alt"></i></div>
      <div style="font-size:.95em;font-weight:700;color:#e6edf3;margin-bottom:6px">Drop Sysmon XML logs here</div>
      <div style="font-size:.8em;color:#8b949e;margin-bottom:12px">Supports single or multiple XML files from Sysmon event logs</div>
      <button style="background:linear-gradient(135deg,#1d3461,#1d6ae5);border:none;color:#fff;padding:8px 20px;border-radius:8px;cursor:pointer;font-size:.83em;font-weight:600">
        <i class="fas fa-folder-open" style="margin-right:6px"></i>Browse Files
      </button>
      <input type="file" id="sysmonFileInput" accept=".xml" multiple style="display:none" onchange="_sysmonFileSelected(event)" />
    </div>

    <!-- Sample Data Button -->
    <div style="text-align:center;margin-top:10px">
      <button onclick="_sysmonLoadSample()" style="background:none;border:1px solid #1a2640;color:#8b949e;padding:5px 14px;border-radius:6px;cursor:pointer;font-size:.78em">
        <i class="fas fa-flask" style="margin-right:5px;color:#c9a227"></i>Load Sample Sysmon Log
      </button>
    </div>

    <!-- Analysis Results (hidden until data loaded) -->
    <div id="sysmonResults" style="display:none;margin-top:20px"></div>
  </div>`;
}

/* File drop handler */
window._sysmonDrop = (e) => {
  e.preventDefault();
  document.getElementById('sysmonUploadZone')?.classList.remove('drag-over');
  const files = Array.from(e.dataTransfer.files).filter(f => f.name.endsWith('.xml'));
  if (files.length) _processFiles(files);
  else if (typeof showToast === 'function') showToast('Please drop .xml Sysmon log files', 'warning');
};

window._sysmonFileSelected = (e) => {
  const files = Array.from(e.target.files);
  if (files.length) _processFiles(files);
};

async function _processFiles(files) {
  const resultsEl = document.getElementById('sysmonResults');
  if (!resultsEl) return;
  resultsEl.style.display = 'block';
  resultsEl.innerHTML = `
    <div style="text-align:center;padding:32px">
      <i class="fas fa-spinner fa-spin" style="font-size:2em;color:#c9a227;margin-bottom:12px;display:block"></i>
      <div style="font-size:.85em;color:#8b949e">Parsing ${files.length} file(s) and analyzing events…</div>
    </div>`;

  try {
    const allEvents = [];
    for (const file of files) {
      const text   = await file.text();
      const events = _parseSysmonXML(text);
      allEvents.push(...events);
    }

    if (!allEvents.length) {
      resultsEl.innerHTML = `<div style="text-align:center;padding:32px;color:#8b949e">No Sysmon events found in uploaded files. Make sure the XML contains valid Sysmon event data.</div>`;
      return;
    }

    const analysis = _analyzeSysmonEvents(allEvents);
    _renderAnalysisResults(resultsEl, allEvents, analysis);

    if (typeof showToast === 'function') {
      showToast(`Analyzed ${allEvents.length} events — threat score: ${analysis.threatScore}`, analysis.threatScore >= 70 ? 'error' : analysis.threatScore >= 40 ? 'warning' : 'success');
    }
  } catch (err) {
    resultsEl.innerHTML = `<div style="text-align:center;padding:32px;color:#ef4444">
      <i class="fas fa-exclamation-triangle" style="font-size:2em;margin-bottom:10px;display:block"></i>
      Parse Error: ${err.message}
    </div>`;
  }
}

/* ─────────────────────────────────────────────
   SAMPLE LOG GENERATOR
───────────────────────────────────────────── */
window._sysmonLoadSample = () => {
  const sampleXML = `<?xml version="1.0" encoding="UTF-8"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
      <EventID>1</EventID>
      <TimeCreated SystemTime="${new Date(Date.now()-3600000).toISOString()}" />
      <Computer>WORKSTATION-01</Computer>
    </System>
    <EventData>
      <Data Name="RuleName">-</Data>
      <Data Name="UtcTime">${new Date(Date.now()-3600000).toISOString()}</Data>
      <Data Name="ProcessGuid">{A23EAE89-BD2E-5C35-0000-0010E9D95E00}</Data>
      <Data Name="Image">C:\\Windows\\System32\\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==</Data>
      <Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="User">DOMAIN\\Administrator</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
      <EventID>8</EventID>
      <TimeCreated SystemTime="${new Date(Date.now()-3500000).toISOString()}" />
      <Computer>WORKSTATION-01</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Users\\user\\AppData\\Local\\Temp\\malware.exe</Data>
      <Data Name="TargetImage">C:\\Windows\\System32\\svchost.exe</Data>
      <Data Name="StartAddress">0x7FFB8D460000</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
      <EventID>10</EventID>
      <TimeCreated SystemTime="${new Date(Date.now()-3400000).toISOString()}" />
      <Computer>WORKSTATION-01</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Users\\user\\AppData\\Roaming\\mimikatz.exe</Data>
      <Data Name="TargetImage">C:\\Windows\\System32\\lsass.exe</Data>
      <Data Name="GrantedAccess">0x1FFFFF</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
      <EventID>22</EventID>
      <TimeCreated SystemTime="${new Date(Date.now()-3300000).toISOString()}" />
      <Computer>WORKSTATION-01</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\svchost.exe</Data>
      <Data Name="QueryName">xwxzaknbvpqrstuvwxyz.evil-c2-domain.ru</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
      <EventID>3</EventID>
      <TimeCreated SystemTime="${new Date(Date.now()-3200000).toISOString()}" />
      <Computer>WORKSTATION-01</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\powershell.exe</Data>
      <Data Name="DestinationIp">185.220.101.45</Data>
      <Data Name="DestinationPort">4444</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
      <EventID>13</EventID>
      <TimeCreated SystemTime="${new Date(Date.now()-3100000).toISOString()}" />
      <Computer>WORKSTATION-01</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\reg.exe</Data>
      <Data Name="TargetObject">HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater</Data>
      <Data Name="Details">C:\\Users\\user\\AppData\\Roaming\\update.exe</Data>
    </EventData>
  </Event>
</Events>`;

  // Parse as blob
  const blob = new Blob([sampleXML], {type:'application/xml'});
  const file = new File([blob], 'sample-sysmon.xml', {type:'application/xml'});
  _processFiles([file]);
};

/* ─────────────────────────────────────────────
   RENDER ANALYSIS RESULTS
───────────────────────────────────────────── */
function _renderAnalysisResults(container, events, analysis) {
  const { findings, timeline, eventStats, threatScore } = analysis;
  const scoreColor = threatScore >= 70 ? '#ef4444' : threatScore >= 40 ? '#f97316' : threatScore >= 20 ? '#f59e0b' : '#22c55e';
  const scoreLabel = threatScore >= 70 ? 'CRITICAL' : threatScore >= 40 ? 'HIGH' : threatScore >= 20 ? 'MEDIUM' : 'LOW';
  const allMitre   = [...new Set(findings.flatMap(f => f.mitre))];

  container.innerHTML = `
  <!-- Score Banner -->
  <div style="background:linear-gradient(135deg,rgba(${threatScore>=70?'239,68,68':threatScore>=40?'249,115,22':'245,158,11'},0.12),rgba(5,8,15,.6));
    border:1px solid ${scoreColor}44;border-radius:12px;padding:20px;margin-bottom:16px;display:flex;align-items:center;gap:20px">
    <div style="text-align:center;flex-shrink:0">
      <div style="font-size:2.8em;font-weight:900;color:${scoreColor};line-height:1">${threatScore}</div>
      <div style="font-size:.7em;color:${scoreColor};font-weight:700;text-transform:uppercase;letter-spacing:1px">${scoreLabel} THREAT</div>
    </div>
    <div>
      <div style="font-size:1em;font-weight:700;color:#e6edf3;margin-bottom:4px">Threat Score Analysis</div>
      <div style="font-size:.8em;color:#8b949e;line-height:1.6">
        <strong style="color:#e6edf3">${events.length}</strong> total events · 
        <strong style="color:${scoreColor}">${findings.length}</strong> suspicious patterns detected · 
        <strong style="color:#c9a227">${allMitre.length}</strong> MITRE techniques identified
      </div>
    </div>
    <button onclick="_sysmonInvestigateAI()" style="margin-left:auto;background:linear-gradient(135deg,#1d3461,#c9a227);border:none;color:#fff;padding:10px 18px;border-radius:8px;cursor:pointer;font-size:.8em;font-weight:700;white-space:nowrap;flex-shrink:0">
      <i class="fas fa-robot" style="margin-right:6px"></i>Investigate with AI
    </button>
  </div>

  <!-- Stats Grid -->
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin-bottom:16px">
    ${Object.entries(eventStats).slice(0,6).map(([eid,count])=>{
      const evDef = SYSMON_EVENTS[parseInt(eid)] || SYSMON_EVENTS[255];
      return `<div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:10px;text-align:center">
        <div style="font-size:1.3em;font-weight:800;color:#22d3ee">${count}</div>
        <div style="font-size:.68em;color:#8b949e;margin-top:2px"><i class="fas ${evDef.icon}" style="color:#c9a227;margin-right:3px"></i>${evDef.name.slice(0,20)}</div>
        <div style="font-size:.65em;color:#4a6080">Event ID ${eid}</div>
      </div>`;
    }).join('')}
  </div>

  <!-- MITRE Techniques -->
  ${allMitre.length ? `<div style="background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:14px;margin-bottom:14px">
    <div style="font-size:.82em;font-weight:700;color:#e6edf3;margin-bottom:10px"><i class="fas fa-th" style="color:#3b82f6;margin-right:6px"></i>MITRE ATT&CK Techniques Detected</div>
    <div style="display:flex;flex-wrap:wrap;gap:6px">${allMitre.map(t=>`<span style="background:rgba(29,106,229,.1);border:1px solid rgba(29,106,229,.3);color:#3b82f6;padding:4px 10px;border-radius:6px;font-family:monospace;font-size:.78em;font-weight:600">${t}</span>`).join('')}</div>
  </div>` : ''}

  <!-- Tabs: Findings / Timeline -->
  <div style="display:flex;gap:4px;border-bottom:1px solid #1e2d3d;margin-bottom:14px">
    <button onclick="_sysmonTab(0)" id="sysTabBtn-0" style="padding:7px 14px;background:#1d6ae5;border:1px solid #1d6ae5;border-bottom:none;color:#fff;cursor:pointer;border-radius:6px 6px 0 0;font-size:.82em;font-weight:600">
      <i class="fas fa-exclamation-triangle" style="margin-right:5px;color:#f97316"></i>Findings (${findings.length})
    </button>
    <button onclick="_sysmonTab(1)" id="sysTabBtn-1" style="padding:7px 14px;background:#21262d;border:1px solid #30363d;border-bottom:none;color:#8b949e;cursor:pointer;border-radius:6px 6px 0 0;font-size:.82em">
      <i class="fas fa-stream" style="margin-right:5px"></i>Full Timeline (${timeline.filter(t=>t.type==='alert').length} alerts / ${events.length} events)
    </button>
  </div>

  <!-- Findings Panel -->
  <div id="sysTab-0">
    ${findings.length === 0 ?
      `<div style="text-align:center;padding:32px;color:#22c55e"><i class="fas fa-shield-alt" style="font-size:2.5em;margin-bottom:12px;display:block"></i>No suspicious patterns detected — log appears clean</div>` :
      findings.map(f => `
      <div style="background:#0d1117;border:1px solid ${f.severity==='critical'?'rgba(239,68,68,.3)':f.severity==='high'?'rgba(249,115,22,.2)':'#21262d'};border-radius:10px;padding:14px;margin-bottom:10px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
          <span style="font-size:.72em;font-weight:700;padding:2px 8px;border-radius:8px;text-transform:uppercase;
            background:${f.severity==='critical'?'rgba(239,68,68,.15)':f.severity==='high'?'rgba(249,115,22,.12)':'rgba(245,158,11,.1)'};
            color:${f.severity==='critical'?'#ef4444':f.severity==='high'?'#f97316':'#f59e0b'};
            border:1px solid ${f.severity==='critical'?'rgba(239,68,68,.3)':f.severity==='high'?'rgba(249,115,22,.25)':'rgba(245,158,11,.2)'}">
            ${f.severity}
          </span>
          <span style="font-size:.85em;font-weight:700;color:#e6edf3">${f.patternName}</span>
          <span style="font-size:.72em;color:#4a6080;margin-left:auto">${f.patternId}</span>
        </div>
        <div style="font-size:.79em;color:#8b949e;line-height:1.5;margin-bottom:8px">${f.desc}</div>
        <div style="font-size:.77em;color:#8b949e;margin-bottom:6px">
          <span style="color:#22d3ee">Process:</span> <code style="font-family:monospace;color:#e6edf3">${(f.image||'—').slice(0,80)}</code>
        </div>
        ${f.cmdLine !== '—' ? `<div style="font-size:.75em;color:#8b949e;margin-bottom:8px">
          <span style="color:#f97316">Command:</span> <code style="font-family:monospace;font-size:.9em;color:#fbbf24;word-break:break-all">${f.cmdLine.slice(0,160)}</code>
        </div>` : ''}
        <div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center">
          ${f.mitre.map(t=>`<span style="background:rgba(29,106,229,.1);border:1px solid rgba(29,106,229,.3);color:#3b82f6;padding:1px 7px;border-radius:5px;font-family:monospace;font-size:.72em">${t}</span>`).join('')}
          <span style="font-size:.72em;color:#4a6080;margin-left:auto">${new Date(f.time).toLocaleString()}</span>
          <span style="font-size:.72em;color:#4a6080">${f.computer}</span>
        </div>
      </div>`).join('')}
  </div>

  <!-- Timeline Panel -->
  <div id="sysTab-1" style="display:none">
    <div style="max-height:500px;overflow-y:auto">
      ${timeline.map(t => {
        const isAlert = t.type === 'alert';
        const c = t.severity==='critical'?'#ef4444':t.severity==='high'?'#f97316':t.severity==='medium'?'#f59e0b':t.severity==='info'?'#22d3ee':'#8b949e';
        return `<div style="display:flex;gap:10px;padding:7px 4px;border-bottom:1px solid #0f172a;${isAlert?'background:rgba(239,68,68,.03)':''}" onmouseover="this.style.background='#0d1117'" onmouseout="this.style.background='${isAlert?'rgba(239,68,68,.03)':''}'">
          <div style="width:4px;min-height:30px;border-radius:2px;background:${c};flex-shrink:0;margin-top:2px"></div>
          <div style="flex:1;min-width:0">
            <div style="display:flex;align-items:center;gap:6px;margin-bottom:1px">
              ${isAlert?`<span style="font-size:.65em;padding:1px 5px;border-radius:4px;background:${c}22;color:${c};border:1px solid ${c}44;font-weight:700;text-transform:uppercase">${t.severity}</span>`:''}
              <span style="font-size:.8em;color:${isAlert?'#e6edf3':'#8b949e'};font-weight:${isAlert?'600':'400'}">${t.text}</span>
              ${t.eventID?`<span style="font-size:.68em;color:#4a6080">EID:${t.eventID}</span>`:''}
              <span style="font-size:.68em;color:#4a6080;margin-left:auto">${new Date(t.time).toLocaleTimeString()}</span>
            </div>
            <div style="font-size:.74em;color:#4a6080;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${t.detail}</div>
          </div>
        </div>`;
      }).join('')}
    </div>
  </div>`;

  // Store for AI investigation
  window._lastSysmonAnalysis = { events, analysis };
}

window._sysmonTab = (idx) => {
  for(let i=0;i<2;i++){
    const btn=document.getElementById(`sysTabBtn-${i}`);
    const tab=document.getElementById(`sysTab-${i}`);
    if(btn){ btn.style.background=i===idx?'#1d6ae5':'#21262d'; btn.style.borderColor=i===idx?'#1d6ae5':'#30363d'; btn.style.color=i===idx?'#fff':'#8b949e'; }
    if(tab) tab.style.display=i===idx?'block':'none';
  }
};

window._sysmonInvestigateAI = () => {
  const analysis = window._lastSysmonAnalysis;
  if (!analysis) return;
  const { findings, analysis: a } = analysis;
  const top = findings.slice(0,3).map(f => `- ${f.patternName} (${f.mitre.join(',')})`).join('\n');
  const query = `Analyze Sysmon log findings. Threat Score: ${a.threatScore}/100 (${a.threatScore>=70?'CRITICAL':a.threatScore>=40?'HIGH':'MEDIUM'})\n\nTop suspicious patterns:\n${top}\n\nMITRE techniques: ${[...new Set(findings.flatMap(f=>f.mitre))].join(', ')}\n\nProvide: 1) Attack chain reconstruction, 2) IOC extraction, 3) Containment recommendations`;
  navigateTo('ai-orchestrator');
  setTimeout(() => {
    const inp = document.getElementById('aiInput');
    if (inp) { inp.value = query; inp.dispatchEvent(new Event('input')); }
    if (typeof sendAIMessage === 'function') sendAIMessage();
  }, 500);
};

/* ─────────────────────────────────────────────
   EXPORTS
───────────────────────────────────────────── */
window.renderSysmonAnalyzer = renderSysmonAnalyzer;
window.renderSysmon         = renderSysmonAnalyzer;
