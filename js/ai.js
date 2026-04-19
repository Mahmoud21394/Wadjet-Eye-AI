/* ══════════════════════════════════════════════════════════
   ArgusWatch — AI Orchestrator Module
   Simulates the Agentic AI investigation flow
   ══════════════════════════════════════════════════════════ */

let currentProvider = 'ollama';
let aiIterations = 0;
const MAX_ITERATIONS = 12;
let isAIThinking = false;

/* ────────────────── AI PROVIDER CONFIGS ────────────────── */
const AI_PROVIDERS = {
  ollama: { name: 'Qwen3:8B via Ollama', color: '#22d3ee', speed: 'Local · GPU · 2-5s', free: true },
  claude: { name: 'Claude 3.5 Sonnet', color: '#f59e0b', speed: 'API · ~3-8s', free: false },
  openai: { name: 'GPT-4o', color: '#10b981', speed: 'API · ~2-6s', free: false },
  gemini: { name: 'Gemini 2.0 Flash', color: '#8b5cf6', speed: 'API · ~1-4s', free: false },
};

/* ────────────────── TOOL DEFINITIONS ────────────────── */
const AI_TOOLS = {
  whois_lookup: {
    desc: 'WHOIS registration data for domains and IPs',
    exec: (q) => ({
      registrar: 'Namecheap, Inc.',
      created: '2024-11-28',
      expires: '2025-11-28',
      nameservers: ['ns1.namecheap.com', 'ns2.namecheap.com'],
      registrant: 'Privacy Protected',
      status: 'clientTransferProhibited',
    })
  },
  virustotal_check: {
    desc: 'Multi-AV and threat reputation from VirusTotal',
    exec: (q) => ({
      malicious: Math.floor(Math.random() * 45) + 5,
      suspicious: Math.floor(Math.random() * 10),
      total: 71,
      categories: ['malware', 'c2', 'phishing'],
      last_analysis: new Date().toISOString().slice(0,10),
    })
  },
  shodan_query: {
    desc: 'Internet-exposed service and port intelligence from Shodan',
    exec: (q) => ({
      ports: [443, 80, 22, 8080],
      services: ['nginx/1.18.0', 'OpenSSH 8.2', 'Apache httpd'],
      country: 'Netherlands',
      asn: 'AS44477 STARK INDUSTRIES SOLUTIONS LTD',
      vulns: ['CVE-2023-44487', 'CVE-2024-1086'],
    })
  },
  cve_lookup: {
    desc: 'CVE details, CVSS scores, and exploit status',
    exec: (q) => ({
      cve_id: q.match(/CVE-\d{4}-\d+/)?.[0] || 'CVE-2024-3400',
      cvss: 10.0,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      epss: 0.973,
      kev: true,
      patch_available: true,
      exploit_public: true,
    })
  },
  mitre_map: {
    desc: 'Map observables to MITRE ATT&CK techniques',
    exec: (q) => ({
      techniques: ['T1566.001', 'T1078', 'T1059.001', 'T1486'],
      tactic: ['Initial Access', 'Execution', 'Impact'],
      confidence: 87,
      actor_matches: ['APT29', 'FIN7'],
    })
  },
  urlscan_submit: {
    desc: 'Submit URL for sandbox analysis and screenshot',
    exec: (q) => ({
      verdict: 'malicious',
      categories: ['phishing', 'malware'],
      screenshot_url: 'https://urlscan.io/screenshots/...',
      dom_urls: ['cdn-malicious.ru/payload.exe'],
      ip: '185.220.101.' + Math.floor(Math.random()*254),
    })
  },
  abuseipdb_check: {
    desc: 'IP abuse history and reputation from AbuseIPDB',
    exec: (q) => ({
      confidence: Math.floor(Math.random() * 40) + 55,
      reports: Math.floor(Math.random() * 1000) + 100,
      categories: ['Port Scan', 'Hacking', 'C2'],
      last_reported: '2024-12-14',
      country: 'RU',
      isp: 'Stark Industries Solutions Ltd',
    })
  },
  otx_pulse: {
    desc: 'AlienVault OTX threat pulses and indicators',
    exec: (q) => ({
      pulses: Math.floor(Math.random() * 20) + 3,
      indicators: Math.floor(Math.random() * 50) + 10,
      tags: ['c2', 'malware', 'apt'],
      related_actors: ['APT29', 'Lazarus Group'],
    })
  },
  passive_dns: {
    desc: 'Historical DNS resolution data and infrastructure mapping',
    exec: (q) => ({
      resolutions: [
        { ip: '185.220.101.45', first_seen: '2024-11-28', last_seen: '2024-12-14' },
        { ip: '45.142.212.100', first_seen: '2024-12-01', last_seen: '2024-12-10' },
      ],
      subdomains: ['mail', 'cdn', 'update', 'api'],
      mx_records: [],
    })
  },
};

/* ────────────────── RESPONSE TEMPLATES ────────────────── */
const AI_RESPONSES = [
  {
    patterns: ['185.220.101', 'c2', 'botnet', 'malicious ip'],
    thinking_steps: [
      'Checking IP reputation across 47 threat feeds...',
      'Querying AbuseIPDB — 1,247 abuse reports found',
      'Running Shodan query — Cobalt Strike beacon detected on 443/tcp',
      'Cross-referencing with Feodo Tracker C2 blocklist...',
      'Running passive DNS pivot — 3 related domains identified',
      'Mapping to MITRE ATT&CK: T1071.001, T1090.003',
    ],
    tools_used: ['abuseipdb_check', 'shodan_query', 'otx_pulse', 'passive_dns', 'mitre_map'],
    conclusion: 'MALICIOUS — HIGH CONFIDENCE',
    summary: `## 🔴 MALICIOUS IP — Immediate Block Recommended

**IP:** 185.220.101.45  
**Classification:** Active C2 Infrastructure (Emotet / Cobalt Strike)  
**Confidence:** 94%

### Evidence Trail
1. **AbuseIPDB** — 1,247 reports | Confidence: 97% | Categories: Hacking, C2, Port Scan
2. **Shodan** — Port 443/tcp TLS fingerprint matches Cobalt Strike Team Server beacon
3. **Feodo Tracker** — Listed in C2 blocklist since 2024-11-28
4. **Passive DNS** — 3 related domains: \`c2-update[.]ru\`, \`beacon-cdn[.]net\`, \`admin-panel[.]cc\`
5. **OTX** — 12 threat pulses reference this IP, tagged: emotet, cobalt_strike, apt

### MITRE ATT&CK Mapping
- **T1071.001** — Application Layer Protocol: Web Protocols (C2 communication)
- **T1090.003** — Proxy: Multi-hop Proxy (Tor exit node used for obfuscation)
- **T1041** — Exfiltration Over C2 Channel

### Recommended Actions
- 🚫 **Block immediately** at perimeter firewall
- 🔍 Check all customer logs for connections to this IP in past 30 days
- 📤 Add to all customer SIEM blocklists
- 🎯 Attribute to **Emotet affiliate** operating Cobalt Strike infrastructure`,
  },
  {
    patterns: ['cve-2024-3400', 'palo alto', 'pan-os', 'globalprotect', 'rce'],
    thinking_steps: [
      'Looking up CVE-2024-3400 in NVD and CISA KEV...',
      'Checking EPSS score — 97.3% exploitation probability',
      'Scanning for related exploit code in public repositories...',
      'Cross-referencing with ThreatFox for C2 infrastructure...',
      'Mapping exploitation activity to MITRE ATT&CK...',
      'Checking customer asset inventory for affected versions...',
    ],
    tools_used: ['cve_lookup', 'shodan_query', 'otx_pulse', 'virustotal_check', 'mitre_map'],
    conclusion: 'CRITICAL — Patch Immediately',
    summary: `## 🔴 CRITICAL CVE — Active Exploitation Confirmed

**CVE:** CVE-2024-3400  
**Product:** PAN-OS GlobalProtect (Palo Alto Networks)  
**CVSS:** 10.0 (CRITICAL) | **EPSS:** 97.3%  
**CISA KEV:** ✅ Added 2024-04-12

### Vulnerability Details
Command injection vulnerability in PAN-OS GlobalProtect gateway. Allows unauthenticated remote code execution as root. No interaction required.

### Active Exploitation Evidence
1. **CISA KEV** — Confirmed actively exploited in the wild
2. **NVD** — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
3. **EPSS** — 97.3% probability of exploitation (99th percentile)
4. **ThreatFox** — 12 C2 IPs attributed to exploitation campaigns
5. **VT** — 23 public exploit samples, first seen 2024-04-10
6. **Shodan** — 82,000+ internet-facing PAN-OS GlobalProtect instances

### MITRE ATT&CK Mapping
- **T1190** — Exploit Public-Facing Application
- **T1059** — Command and Scripting Interpreter
- **T1078** — Valid Accounts (post-exploitation)

### Customer Impact Assessment
| Customer | Exposed Instances | Patched | Risk |
|---|---|---|---|
| HackerOne | 2 | No | 🔴 CRITICAL |
| Bugcrowd | 1 | Yes | ✅ OK |
| Synack | 3 | No | 🔴 CRITICAL |

### Immediate Actions Required
- 🔴 **Patch NOW** — PAN-OS 10.2.9-h1, 11.0.4-h1, 11.1.2-h3
- 🛑 Disable GlobalProtect gateway if patch cannot be applied immediately
- 🔍 Review logs for exploitation indicators: \`/var/log/pan/gp*\``,
  },
  {
    patterns: ['maliciousupdate', 'ru', 'domain', 'attribution', 'phishing', 'apt29'],
    thinking_steps: [
      'Running WHOIS lookup on maliciousupdate[.]ru...',
      'Checking passive DNS history...',
      'Querying PhishTank and OpenPhish...',
      'Running VirusTotal domain scan...',
      'Cross-referencing infrastructure with known APT29 TTPs...',
      'Analyzing TLS certificate transparency logs...',
      'Pivoting on nameservers and registrar patterns...',
    ],
    tools_used: ['whois_lookup', 'passive_dns', 'virustotal_check', 'urlscan_submit', 'mitre_map', 'otx_pulse'],
    conclusion: 'HIGH — APT29 Phishing Infrastructure',
    summary: `## 🟠 THREAT ACTOR ATTRIBUTION — APT29 (Cozy Bear)

**Domain:** maliciousupdate[.]ru  
**Classification:** Spear-phishing infrastructure  
**Attribution:** APT29 / Midnight Blizzard (HIGH confidence — 87%)

### Infrastructure Analysis
1. **WHOIS** — Registered 2024-12-10, Namecheap, privacy-protected, RU TLD
2. **Passive DNS** — IP 185.220.101.45 (known APT29 infrastructure)
3. **TLS Cert** — Let's Encrypt cert obtained 12h after registration (rapid deployment pattern)
4. **URLScan** — Page mimics Windows Update portal with malicious payload delivery
5. **VirusTotal** — 34/71 AV detections, classified as trojan downloader

### APT29 Indicators (TTPs Match)
| Indicator | APT29 Pattern | Match |
|---|---|---|
| RU TLD domain | ✅ Frequent | High |
| Privacy-protected registration | ✅ Always | High |
| Namecheap registrar | ✅ Common | Medium |
| Let's Encrypt cert, rapid | ✅ Signature | High |
| Windows Update lure | ✅ Known campaign | High |
| Cobalt Strike C2 | ✅ Primary tool | High |

### Campaign Attribution
This domain is part of **Operation Midnight Rain** — APT29's ongoing campaign targeting security researchers and bug bounty platforms.

### MITRE ATT&CK
- **T1566.002** — Phishing: Spear-phishing Link
- **T1583.001** — Acquire Infrastructure: Register Domains
- **T1036** — Masquerading (impersonating Windows Update)`,
  },
  {
    patterns: ['hackerone', 'critical', 'findings', 'summary', 'brief', 'report'],
    thinking_steps: [
      'Querying findings database for customer: HackerOne...',
      'Filtering by severity: CRITICAL...',
      'Cross-referencing with active campaigns...',
      'Calculating risk scores and priorities...',
    ],
    tools_used: ['mitre_map'],
    conclusion: '3 CRITICAL findings require immediate action',
    summary: `## 📊 HackerOne — Critical Findings Summary

**Report Generated:** ${new Date().toLocaleString()}  
**Total Findings:** 89 | **Critical:** 3 | **High:** 24 | **Medium:** 38 | **Low:** 24

---

### 🔴 CRITICAL #1 — F001: Google API Key Exposed
- **Value:** \`AIzaSyD-REDACTED-8xK9mN3pQ\`
- **Source:** GitHub Gist (public)
- **Score:** 96/100
- **Status:** Key ACTIVE — Maps API + Cloud Billing access confirmed
- **Action:** Rotate key immediately via Google Cloud Console

### 🔴 CRITICAL #2 — F002: Infostealer VPN Credential
- **Value:** \`admin:P@ssw0rd123! → corp-vpn.hackerone.com\`
- **Source:** HudsonRock infostealer corpus
- **Score:** 94/100
- **Breach Date:** 3 days ago (Redline Stealer)
- **Action:** Force password reset, enable MFA, review VPN logs

### 🔴 CRITICAL #3 — F008: SSH Private Key in Public Repo
- **Value:** RSA 4096-bit key for \`dev@prod-api-server\`
- **Source:** GitHub Secrets Scanner
- **Score:** 76/100
- **Action:** Revoke key immediately, rotate all production SSH keys

---

### Risk Summary
- **Threat Pressure Index:** 74/100 (HIGH)
- **Active Campaigns:** 5 (including APT29 "Operation Midnight Rain")
- **MITRE Coverage:** 87 techniques detected this week`,
  },
];

/* ────────────────── CHAT FUNCTIONS ────────────────── */
function handleAIKey(event) {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    sendAIMessage();
  }
}

function sendSuggestion(btn) {
  const input = document.getElementById('aiInput');
  if (input) {
    input.value = btn.textContent;
    sendAIMessage();
  }
}

function loadInvestigation(query) {
  const input = document.getElementById('aiInput');
  if (input) {
    input.value = query;
  }
}

async function sendAIMessage() {
  const input = document.getElementById('aiInput');
  const sendBtn = document.getElementById('aiSendBtn');
  if (!input || isAIThinking) return;

  const message = input.value.trim();
  if (!message) return;

  // Append user message
  appendMessage('user', message);
  input.value = '';
  input.style.height = 'auto';
  isAIThinking = true;
  sendBtn.disabled = true;
  aiIterations = 0;

  // Find best response template
  const template = findBestTemplate(message);

  // Show thinking indicator
  const thinkingId = appendThinking();

  // Simulate agentic reasoning steps
  await simulateAgenticProcess(template, thinkingId, message);

  isAIThinking = false;
  sendBtn.disabled = false;
}

function appendMessage(role, content) {
  const container = document.getElementById('aiMessages');
  if (!container) return;

  const div = document.createElement('div');
  div.className = `msg-${role}`;

  if (role === 'user') {
    div.innerHTML = `
      <div class="msg-avatar">A</div>
      <div class="msg-bubble">${escapeHtml(content)}</div>
    `;
  } else {
    div.innerHTML = `
      <div class="msg-avatar"><i class="fas fa-robot"></i></div>
      <div class="msg-bubble">${formatMarkdown(content)}</div>
    `;
  }

  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return div;
}

function appendThinking() {
  const container = document.getElementById('aiMessages');
  if (!container) return null;

  const div = document.createElement('div');
  div.className = 'msg-ai';
  div.id = 'thinkingIndicator';
  div.innerHTML = `
    <div class="msg-avatar"><i class="fas fa-robot"></i></div>
    <div class="msg-bubble">
      <div class="msg-thinking">
        <div class="thinking-dots">
          <span></span><span></span><span></span>
        </div>
        <span id="thinkingText">Initializing autonomous investigation...</span>
      </div>
    </div>
  `;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return div;
}

async function simulateAgenticProcess(template, thinkingEl, originalQuery) {
  const iterLabel = document.getElementById('aiIterLabel');
  const steps = template.thinking_steps;
  const tools = template.tools_used;

  // Update evidence trail
  clearEvidenceTrail();

  // Run through reasoning steps
  for (let i = 0; i < steps.length; i++) {
    aiIterations++;
    if (iterLabel) iterLabel.textContent = `${aiIterations}/${MAX_ITERATIONS} iterations`;

    const thinkingText = document.getElementById('thinkingText');
    if (thinkingText) thinkingText.textContent = steps[i];

    // Add tool execution log
    if (tools[i]) {
      const toolData = AI_TOOLS[tools[i]];
      if (toolData) {
        const result = toolData.exec(originalQuery);
        addToolLog(tools[i], result);
        addEvidenceItem(tools[i], result);
      }
    }

    await sleep(400 + Math.random() * 600);
  }

  // Remove thinking indicator
  if (thinkingEl && thinkingEl.parentNode) {
    thinkingEl.parentNode.removeChild(thinkingEl);
  }

  if (iterLabel) iterLabel.textContent = `${aiIterations}/${MAX_ITERATIONS} iterations`;

  // Append tool usage block + final answer
  const container = document.getElementById('aiMessages');
  if (!container) return;

  const providerCfg = AI_PROVIDERS[currentProvider];
  const msgDiv = document.createElement('div');
  msgDiv.className = 'msg-ai';
  msgDiv.innerHTML = `
    <div class="msg-avatar"><i class="fas fa-robot"></i></div>
    <div style="flex:1;">
      <div class="msg-tool-use">
        🛠️ Used ${tools.length} tool${tools.length>1?'s':''}: ${tools.join(', ')} · ${aiIterations} iterations · ${providerCfg.name}
      </div>
      <div class="msg-bubble" style="margin-top:6px;">
        ${formatMarkdown(template.summary)}
      </div>
      <div class="msg-evidence">
        ✅ Conclusion: <strong>${template.conclusion}</strong>
      </div>
    </div>
  `;
  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;

  // Show toast
  showToast(`AI Investigation complete: ${template.conclusion}`, 'success');
}

function findBestTemplate(message) {
  const msg = message.toLowerCase();
  for (const t of AI_RESPONSES) {
    if (t.patterns.some(p => msg.includes(p.toLowerCase()))) {
      return t;
    }
  }
  // Default generic response
  return {
    thinking_steps: [
      'Analyzing query and identifying relevant IOC types...',
      'Searching threat intelligence databases...',
      'Correlating with active campaigns...',
      'Mapping to MITRE ATT&CK framework...',
      'Generating evidence-backed conclusion...',
    ],
    tools_used: ['virustotal_check', 'otx_pulse', 'mitre_map', 'abuseipdb_check'],
    conclusion: 'Analysis complete — see full report',
    summary: `## 🔵 Threat Intelligence Analysis

**Query:** ${escapeHtml(message)}  
**Timestamp:** ${new Date().toLocaleString()}  
**Provider:** ${AI_PROVIDERS[currentProvider].name}

### Analysis Summary
Based on my autonomous investigation across **47 threat feeds** and **9 specialized tools**, I've analyzed your query against our threat intelligence database.

**Key Findings:**
- Cross-referenced against 18,432 active IOCs in database
- Checked against 12 active campaigns
- Verified against MITRE ATT&CK (99 technique coverage)

### What I Found
No immediate critical indicators for this specific query. However, I recommend:
1. **Monitor** for related indicators using continuous collection
2. **Set up alert** for this IOC pattern in your customer environments
3. **Review** the IOC Registry for similar pattern detection

### Confidence Level
Medium confidence — additional context would improve accuracy.

*Need more specific information? Try: "Investigate [IP/domain/CVE/API key]" or "Run threat brief for [customer name]"*`,
  };
}

/* ────────────────── TOOL LOG & EVIDENCE ────────────────── */
function addToolLog(toolName, result) {
  const container = document.getElementById('toolLog');
  if (!container) return;

  const div = document.createElement('div');
  div.className = 'tool-log-item';
  const responseTime = (0.5 + Math.random() * 2).toFixed(1) + 's';
  div.innerHTML = `
    <span class="tool-name">${toolName}</span>
    <span class="tool-status">✓ 200</span>
    <span class="tool-time">${responseTime}</span>
  `;
  container.insertBefore(div, container.firstChild);
  while (container.children.length > 15) container.removeChild(container.lastChild);
}

function clearEvidenceTrail() {
  const container = document.getElementById('evidenceTrail');
  if (container) container.innerHTML = '';
}

function addEvidenceItem(source, data) {
  const container = document.getElementById('evidenceTrail');
  if (!container) return;

  const div = document.createElement('div');
  div.className = 'evidence-item';
  const summary = getDataSummary(source, data);
  div.innerHTML = `
    <span class="evidence-source">${source}</span>
    <div class="evidence-finding">${summary}</div>
  `;
  container.appendChild(div);
}

function getDataSummary(source, data) {
  switch (source) {
    case 'virustotal_check': return `${data.malicious}/${data.total} AV detections`;
    case 'abuseipdb_check': return `${data.reports} reports, ${data.confidence}% confidence`;
    case 'shodan_query': return `${data.ports.length} open ports, ASN: ${data.asn.slice(0,30)}`;
    case 'whois_lookup': return `Registered: ${data.created}, Registrar: ${data.registrar}`;
    case 'passive_dns': return `${data.resolutions.length} resolutions, ${data.subdomains.length} subdomains`;
    case 'mitre_map': return `${data.techniques.length} techniques, actors: ${data.actor_matches.join(', ')}`;
    case 'otx_pulse': return `${data.pulses} pulses, ${data.indicators} indicators`;
    case 'cve_lookup': return `CVSS: ${data.cvss}, EPSS: ${(data.epss*100).toFixed(1)}%`;
    case 'urlscan_submit': return `Verdict: ${data.verdict}, DOM URLs: ${data.dom_urls.length}`;
    default: return JSON.stringify(data).slice(0, 60) + '...';
  }
}

/* ────────────────── AI PROVIDER SWITCHER ────────────────── */
function initAIProviderSwitcher() {
  const switcher = document.getElementById('aiProviderSwitcher');
  const btn = switcher.querySelector('.ai-provider-btn');
  const dropdown = document.getElementById('aiDropdown');

  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    dropdown.classList.toggle('open');
  });

  document.querySelectorAll('.ai-option').forEach(opt => {
    opt.addEventListener('click', () => {
      const provider = opt.dataset.provider;
      switchAIProvider(provider);
      dropdown.classList.remove('open');
    });
  });

  document.addEventListener('click', () => {
    dropdown.classList.remove('open');
  });
}

function switchAIProvider(provider) {
  currentProvider = provider;
  const cfg = AI_PROVIDERS[provider];

  // Update button
  const btn = document.querySelector('.ai-provider-btn');
  btn.innerHTML = `
    <span class="ai-dot" style="background:${cfg.color}"></span>
    <span class="ai-name">${provider === 'ollama' ? 'Qwen3:8B' : cfg.name.split(' ')[0]}</span>
    <span class="ai-subtitle">${provider === 'ollama' ? 'Local · GPU' : 'API'}</span>
  `;

  // Update active option
  document.querySelectorAll('.ai-option').forEach(opt => {
    opt.classList.toggle('active', opt.dataset.provider === provider);
  });

  // Update all checkmarks
  document.querySelectorAll('.ai-check').forEach(c => c.remove());
  document.querySelector(`.ai-option[data-provider="${provider}"]`)?.insertAdjacentHTML('beforeend', '<i class="fas fa-check ai-check"></i>');

  // Update AI chat header
  const label = document.getElementById('aiProviderLabel');
  if (label) label.textContent = cfg.name;

  showToast(`Switched to ${cfg.name}`, 'success');
}

/* ────────────────── MARKDOWN FORMATTER ────────────────── */
function formatMarkdown(text) {
  return text
    // Code blocks
    .replace(/```([^`]+)```/g, '<pre>$1</pre>')
    // Inline code
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // Bold
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    // H2
    .replace(/^## (.+)$/gm, '<h3 style="font-size:13px;font-weight:700;margin:8px 0 4px;color:var(--text-primary);">$1</h3>')
    // H3
    .replace(/^### (.+)$/gm, '<h4 style="font-size:12px;font-weight:700;margin:6px 0 3px;color:var(--text-secondary);">$1</h4>')
    // Horizontal rule
    .replace(/^---$/gm, '<hr style="border:none;border-top:1px solid var(--border);margin:8px 0;">')
    // Table rows (simple)
    .replace(/^\|(.+)\|$/gm, (match, content) => {
      const cells = content.split('|').map(c => c.trim());
      if (cells.every(c => /^[-:]+$/.test(c))) return ''; // skip separator
      return `<div style="display:flex;gap:8px;padding:3px 0;font-size:11px;">${cells.map(c => `<span style="flex:1;min-width:80px;">${c}</span>`).join('')}</div>`;
    })
    // List items
    .replace(/^[•\-\*] (.+)$/gm, '<div style="padding:2px 0 2px 12px;position:relative;font-size:12px;"><span style="position:absolute;left:0;color:var(--accent-blue);">•</span>$1</div>')
    // Numbered items
    .replace(/^(\d+)\. (.+)$/gm, '<div style="padding:2px 0 2px 16px;position:relative;font-size:12px;"><span style="position:absolute;left:0;color:var(--accent-blue);">$1.</span>$2</div>')
    // Emoji headers
    .replace(/^(🔴|🟠|🟡|🟢|🔵|✅|📊|📋|🎯|🛡️|🔍) (.+)$/gm, '<div style="font-size:13px;font-weight:700;margin:6px 0 3px;">$1 $2</div>')
    // Newlines
    .replace(/\n\n/g, '<br><br>')
    .replace(/\n/g, '<br>');
}

/* ────────────────── UTILS ────────────────── */
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
