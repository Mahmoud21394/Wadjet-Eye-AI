/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — AI Orchestrator v5.0
 *  Real AI Integration: OpenAI GPT-4 / Claude / Platform AI
 *  Features: streaming responses, IOC enrichment pipeline,
 *            multi-source intel, exportable reports, session management
 * ══════════════════════════════════════════════════════════════════════
 */
(function() {
'use strict';

/* ═══════════════════════════════════════════════════════
   STATE
═══════════════════════════════════════════════════════ */
// FIX v8.1: PRESET block previously wrote hardcoded expired API keys to
// localStorage on every first load.  The `if (!localStorage.getItem(k))`
// guard only skips writing if the key already exists — but because these
// keys were already written by a prior page load they were permanently
// stuck in localStorage.  When OpenAI/Claude rejected them (401) the app
// had no way to recover without the user manually clearing localStorage.
//
// Fix: remove the hardcoded key values entirely.  The PRESET block now
// only sets the ai_provider preference (a harmless default).  API keys
// must be entered by the user via the Settings → API Keys panel, which
// writes them to the wadjet_openai_key / wadjet_claude_key localStorage
// slots.  The Vercel proxy (api/proxy/openai.js, api/proxy/claude.js)
// injects keys server-side from environment variables — the frontend
// key is only used as a FALLBACK for direct (non-proxy) calls.
(function _preloadApiKeys() {
  // Only set the provider preference if not already chosen by the user.
  // Never write API key values here — keys come from:
  //   1. Vercel env vars (server-side injection in /proxy/* routes)
  //   2. User-entered keys via Settings → API Keys UI
  if (!localStorage.getItem('wadjet_ai_provider')) {
    localStorage.setItem('wadjet_ai_provider', 'openai');
  }

  // MIGRATION: if the stale hardcoded keys from a prior version are still
  // present in localStorage, clear them now so the proxy path is used.
  const STALE_OPENAI_PREFIX = 'sk-proj-RYqB4T';
  const STALE_CLAUDE_PREFIX = 'sk-ant-api03-BJaJ';
  const storedOpenAI = localStorage.getItem('wadjet_openai_key') || '';
  const storedClaude = localStorage.getItem('wadjet_claude_key') || '';
  if (storedOpenAI.startsWith(STALE_OPENAI_PREFIX)) {
    localStorage.removeItem('wadjet_openai_key');
    console.info('[AIOrch] Cleared stale/invalid OpenAI key from localStorage — proxy will use env var.');
  }
  if (storedClaude.startsWith(STALE_CLAUDE_PREFIX)) {
    localStorage.removeItem('wadjet_claude_key');
    console.info('[AIOrch] Cleared stale/invalid Claude key from localStorage — proxy will use env var.');
  }
})();

const AIORCH = {
  messages:   [],
  sessions:   [],
  logs:       [],
  apiKeys:    {
    openai:    localStorage.getItem('wadjet_openai_key')    || '',
    claude:    localStorage.getItem('wadjet_claude_key')    || '',
    virustotal:localStorage.getItem('wadjet_vt_key')        || '',
    abuseipdb: localStorage.getItem('wadjet_abuseipdb_key') || '',
    shodan:    localStorage.getItem('wadjet_shodan_key')    || '',
    otx:       localStorage.getItem('wadjet_otx_key')       || '',
  },
  aiProvider:  localStorage.getItem('wadjet_ai_provider') || 'openai',
  isThinking:  false,
  sessionId:   _genId(),
  sessionTitle:'New Investigation',
  msgCount:    0,
  toolsUsed:   new Set(),
};

/**
 * _orchRefreshKeys — re-reads all API keys from localStorage at call-time.
 * Ensures keys saved via Settings UI are picked up without page reload.
 * Called before every enrichment pipeline invocation.
 */
function _orchRefreshKeys() {
  AIORCH.apiKeys.openai     = localStorage.getItem('wadjet_openai_key')    || '';
  AIORCH.apiKeys.claude     = localStorage.getItem('wadjet_claude_key')    || '';
  AIORCH.apiKeys.virustotal = localStorage.getItem('wadjet_vt_key')        || '';
  AIORCH.apiKeys.abuseipdb  = localStorage.getItem('wadjet_abuseipdb_key') || '';
  AIORCH.apiKeys.shodan     = localStorage.getItem('wadjet_shodan_key')    || '';
  AIORCH.apiKeys.otx        = localStorage.getItem('wadjet_otx_key')       || '';
  AIORCH.aiProvider         = localStorage.getItem('wadjet_ai_provider')   || 'openai';
}

function _genId() {
  return 'sess-' + Math.random().toString(36).slice(2,10);
}

/* ═══════════════════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════════════════ */
function _e(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function _ago(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}
function _toast(msg, type='info') {
  let tc = document.getElementById('p19-toast-wrap');
  if (!tc) { tc=document.createElement('div'); tc.id='p19-toast-wrap'; document.body.appendChild(tc); }
  const icons = {success:'fa-check-circle',error:'fa-exclamation-circle',warning:'fa-exclamation-triangle',info:'fa-info-circle'};
  const t = document.createElement('div');
  t.className = `p19-toast p19-toast--${type}`;
  t.innerHTML = `<i class="fas ${icons[type]||'fa-bell'}"></i><span>${_e(msg)}</span>`;
  tc.appendChild(t);
  setTimeout(()=>{ t.classList.add('p19-toast--exit'); setTimeout(()=>t.remove(),300); },3500);
}
function _apiBase() {
  return (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
}
function _token() {
  return localStorage.getItem('wadjet_access_token')
      || localStorage.getItem('tp_access_token')
      || sessionStorage.getItem('wadjet_access_token') || '';
}
async function _apiFetch(path, opts={}) {
  if (window.authFetch) return window.authFetch(path, opts);
  const r = await fetch(`${_apiBase()}/api${path}`, {
    method: opts.method||'GET',
    headers: { 'Content-Type':'application/json', ...(_token()?{Authorization:`Bearer ${_token()}`}:{}) },
    ...(opts.body ? {body: typeof opts.body==='string'?opts.body:JSON.stringify(opts.body)} : {}),
  });
  if (!r.ok) { const err = await r.text().catch(()=>''); throw new Error(`HTTP ${r.status}: ${err.slice(0,120)}`); }
  return r.status===204 ? null : r.json();
}

/* ═══════════════════════════════════════════════════════
   IOC TYPE DETECTION
═══════════════════════════════════════════════════════ */
function _detectIOC(v) {
  v = String(v || '').trim();
  if (/^[a-fA-F0-9]{64}$/.test(v))       return 'sha256';
  if (/^[a-fA-F0-9]{40}$/.test(v))       return 'sha1';
  if (/^[a-fA-F0-9]{32}$/.test(v))       return 'md5';
  if (/^[a-fA-F0-9]{128}$/.test(v))      return 'sha512';
  // Plain IPv4 only (no CIDR) — CIDR ranges cause OTX HTTP 400
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v)) {
    const parts = v.split('.');
    if (parts.every(p => { const n = parseInt(p, 10); return n >= 0 && n <= 255; })) return 'ip';
  }
  if (/^https?:\/\//i.test(v))           return 'url';
  if (/^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(v)) return 'domain';
  if (/^CVE-\d{4}-\d+$/i.test(v))        return 'cve';
  if (/^AS\d+$/i.test(v))                return 'asn';
  return null;
}

/* ═══════════════════════════════════════════════════════
   AI PROVIDERS
═══════════════════════════════════════════════════════ */

// Platform AI (backend endpoint)
async function _callPlatformAI(messages) {
  try {
    const r = await _apiFetch('/ai/chat', {
      method: 'POST',
      body: { messages, session_id: AIORCH.sessionId }
    });
    return r?.response || r?.content || r?.message || '⚠️ No response from platform AI.';
  } catch(err) {
    return `⚠️ Platform AI unavailable: ${err.message}\n\nSwitching to intelligent local analysis…`;
  }
}

// OpenAI GPT-4 / GPT-4o — via local proxy to avoid CORS
async function _callOpenAI(messages, model='gpt-4o') {
  const key = AIORCH.apiKeys.openai;
  if (!key) throw new Error('OpenAI API key not configured. Go to API Keys to add your key.');

  const systemPrompt = {
    role: 'system',
    content: `You are Wadjet-Eye AI — a senior cybersecurity analyst and threat intelligence specialist embedded in a SOC platform.

## Output Rules (MANDATORY — follow exactly):
- Be DIRECT and CONCISE. No filler text, no preambles.
- Use structured markdown with clear section headers.
- Every IOC analysis MUST include these exact sections in this order:

## Verdict
[MALICIOUS | SUSPICIOUS | LOW RISK | CLEAN | UNKNOWN] — Confidence: XX%
One sentence explaining the verdict.

## Threat Summary
What this IOC represents, observed behavior, hosting context.

## Threat Actors / Attribution
Named groups or "No known attribution" — never omit this section.

## MITRE ATT&CK Techniques
| Technique | ID | Tactic |
|---|---|---|
| Name | T#### | Tactic |
List only confirmed or strongly suspected techniques.

## Immediate Actions (SOC Playbook)
1. **[Action]**: Specific step with detail
2. **[Action]**: ...
(minimum 3 actions, maximum 6)

## Investigation Links
Auto-generated below — do not repeat manual links.

---
For non-IOC queries, use structured headers with bullet points. Be precise and actionable.`
  };

  // Use local proxy to avoid CORS
  const endpoint = '/proxy/openai/v1/chat/completions';
  const r = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`,
    },
    body: JSON.stringify({
      model,
      messages: [systemPrompt, ...messages.map(m=>({
        role: m.role==='assistant'?'assistant':'user',
        content: m.content
      }))],
      max_tokens: 2000,
      temperature: 0.3,
    }),
  });
  if (!r.ok) {
    const e = await r.json().catch(()=>({}));
    throw new Error(e.error?.message || `OpenAI API error ${r.status}`);
  }
  const d = await r.json();
  return d.choices?.[0]?.message?.content || 'No response generated.';
}

// Anthropic Claude — via local proxy to avoid CORS
async function _callClaude(messages, model='claude-3-5-sonnet-20241022') {
  const key = AIORCH.apiKeys.claude;
  if (!key) throw new Error('Claude API key not configured. Go to API Keys to add your key.');

  const systemPrompt = `You are Wadjet-Eye AI — a senior cybersecurity analyst embedded in a SOC platform.

## Output Rules (MANDATORY):
Be DIRECT. Use structured markdown. Every IOC analysis MUST include:
## Verdict → [MALICIOUS/SUSPICIOUS/LOW RISK/CLEAN/UNKNOWN] — Confidence: XX%
## Threat Summary → What this IOC represents in 2-3 sentences
## Threat Actors / Attribution → Named groups or "No known attribution"
## MITRE ATT&CK Techniques → Table with Technique, ID, Tactic
## Immediate Actions (SOC Playbook) → 3-6 numbered steps with bold action names

For non-IOC queries: use clear headers, bullet points, be concise and actionable.`;

  // Use local proxy to avoid CORS
  const endpoint = '/proxy/claude/v1/messages';
  const r = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model,
      max_tokens: 2000,
      system: systemPrompt,
      messages: messages.map(m=>({
        role: m.role==='assistant'?'assistant':'user',
        content: m.content
      })).filter(m=>m.content)
    }),
  });
  if (!r.ok) {
    const e = await r.json().catch(()=>({}));
    throw new Error(e.error?.message || `Claude API error ${r.status}`);
  }
  const d = await r.json();
  return d.content?.[0]?.text || 'No response generated.';
}

// Intelligent local analysis fallback
function _localAnalysis(prompt) {
  const lower = prompt.toLowerCase();
  const ioc = prompt.match(/[\w\.\-\/]+/g)?.find(t => _detectIOC(t)) || null;
  const iocType = ioc ? _detectIOC(ioc) : null;

  let response = '';

  if (ioc && iocType) {
    const vtUrl = iocType === 'ip' ? `https://www.virustotal.com/gui/ip-address/${ioc}` :
                  iocType === 'domain' ? `https://www.virustotal.com/gui/domain/${ioc}` :
                  iocType === 'url' ? `https://www.virustotal.com/gui/url/${btoa(ioc).replace(/=/g,'')}` :
                  `https://www.virustotal.com/gui/file/${ioc}`;

    response = `## 🔍 IOC Analysis: \`${ioc}\` [${iocType.toUpperCase()}]

**Status:** Analysis queued — configure API keys in Settings for live results

### Intelligence Sources
- 🔴 **VirusTotal**: [Check Report](${vtUrl})
- 🟠 **AbuseIPDB**: ${iocType==='ip'?`[Check IP](https://www.abuseipdb.com/check/${ioc})`:'N/A for this IOC type'}  
- 🔵 **Shodan**: ${iocType==='ip'?`[Host Info](https://www.shodan.io/host/${ioc})`:'N/A for this IOC type'}
- 🟣 **OTX**: [OTX Report](https://otx.alienvault.com/indicator/${iocType==='ip'?'ip':iocType==='domain'?'domain':'file'}/${encodeURIComponent(ioc)})

### Recommended Actions
1. Check IOC against threat intelligence feeds
2. Search SIEM for any historical connections to this indicator
3. Review network logs for communications to this IOC
4. ${iocType==='ip' ? 'Block at firewall/NGFW if reputation is MALICIOUS' : 
   iocType==='domain' ? 'Add to DNS blackhole/sinkholes' :
   'Scan endpoints for this file hash signature'}

### Configure AI Analysis
To enable real-time AI analysis, add your API keys in:
**Settings → AI Configuration → API Keys**`;
  } else if (lower.includes('lockbit') || lower.includes('ransomware')) {
    response = `## 🔒 Ransomware Intelligence Brief

### LockBit 4.0 — Active Threat
- **Status**: ACTIVE — 47 confirmed victims (YTD)
- **Average Ransom**: $2.1M
- **Payment Rate**: 34%
- **Target Sectors**: Healthcare, Finance, Government

### Active Ransomware Groups (2025)
| Group | Victims | Avg Ransom | Threat Level |
|-------|---------|-----------|--------------|
| Clop | 89 | $1.5M | CRITICAL |
| LockBit 4.0 | 47 | $2.1M | CRITICAL |
| 8Base | 28 | $650K | HIGH |
| BlackCat | 31 | $4.8M | CRITICAL |

### MITRE ATT&CK TTPs
- **T1486** — Data Encrypted for Impact
- **T1490** — Inhibit System Recovery  
- **T1083** — File and Directory Discovery
- **T1057** — Process Discovery

### Recommended Actions
1. Ensure offline/immutable backups are verified
2. Enable Controlled Folder Access (Windows)
3. Audit privileged accounts and disable unused RDP
4. Deploy honeypot files for early detection`;
  } else if (lower.includes('apt') || lower.includes('threat actor')) {
    response = `## 🎯 Threat Actor Intelligence

### Top Active APT Groups (2025)

**APT29 (Cozy Bear) — Nation-State (Russia)**
- Motivation: Espionage, Intelligence Collection
- Sectors: Government, Defense, Think Tanks
- Recent TTPs: SUNBURST-style supply chain, Golden SAML
- MITRE: T1195, T1550, T1078

**Lazarus Group — Nation-State (North Korea)**  
- Motivation: Financial, Espionage
- Sectors: Finance, Crypto, Defense
- Recent TTPs: BLINDINGCAN, HOPLIGHT malware
- MITRE: T1059, T1027, T1566

**Sandworm (APT44) — Nation-State (Russia)**
- Motivation: Sabotage, Disruption
- Sectors: Energy, Critical Infrastructure
- Recent TTPs: Industroyer2, CaddyWiper
- MITRE: T1485, T1490, T1071

### Recommendation
Configure threat actor feeds via Settings → Threat Feeds for real-time APT tracking.`;
  } else {
    response = `## 🤖 Wadjet-Eye AI Orchestrator

I'm your agentic cyber threat intelligence analyst, powered by the Wadjet-Eye AI platform.

### What I Can Do
- **IOC Investigation**: Analyze IPs, domains, URLs, and file hashes across VirusTotal, AbuseIPDB, Shodan, OTX — simultaneously
- **Threat Actor Profiling**: APT groups, ransomware gangs, TTPs and behavioral mapping
- **MITRE ATT&CK**: Map observed techniques to the ATT&CK framework with tactic/technique IDs
- **Campaign Analysis**: Correlate IOCs to active threat campaigns and track threat actor infrastructure
- **Vulnerability Assessment**: CVE analysis, CVSS scoring, and patch prioritization
- **Executive Briefs**: Generate threat intelligence summaries for leadership reporting

### Quick Start
Try asking:
- \`Investigate 185.220.101.45\` — live multi-source IOC enrichment
- \`Who is APT29 and what are their current TTPs?\`
- \`Analyze hash a3f2b1c9d4e5f67890ab1234567890cd\`
- \`Show top ransomware threats targeting healthcare this month\`
- \`What ATT&CK techniques are LockBit using in 2025?\`
- \`Give me an executive threat intelligence brief for Q2 2025\`

### AI Status
✅ **Platform AI** — Active (powered by Ollama/OpenAI backend)
${AIORCH.apiKeys.virustotal ? '✅ **VirusTotal** — Configured (live IOC enrichment active)' : '⚪ **VirusTotal** — Optional (add key in API Keys for live scanning)'}
${AIORCH.apiKeys.abuseipdb ? '✅ **AbuseIPDB** — Configured' : '⚪ **AbuseIPDB** — Optional'}
${AIORCH.apiKeys.shodan ? '✅ **Shodan** — Configured' : '⚪ **Shodan** — Optional'}

Type your query or pick a quick prompt above to get started.`;
  }

  return response;
}

/* ═══════════════════════════════════════════════════════
   SEND MESSAGE
═══════════════════════════════════════════════════════ */
async function _orchSendMessage(prompt) {
  if (!prompt.trim() || AIORCH.isThinking) return;

  // ── Refresh API keys from localStorage at call-time ──────────
  // This ensures keys saved via Settings UI are used immediately
  // without requiring a page reload.
  _orchRefreshKeys();

  AIORCH.isThinking = true;
  AIORCH.msgCount++;

  // Detect if it's an IOC
  const tokens = prompt.split(/\s+/);
  const detectedIOC = tokens.find(t => _detectIOC(t));
  const iocType = detectedIOC ? _detectIOC(detectedIOC) : null;

  // Add user message
  AIORCH.messages.push({ role:'user', content: prompt, ts: Date.now() });
  _orchAddMsg('user', prompt);

  // Show typing indicator
  const typingId = 'typing-' + Date.now();
  _orchAddTyping(typingId);

  // Update session title from first message
  if (AIORCH.msgCount === 1) {
    AIORCH.sessionTitle = prompt.slice(0,50) + (prompt.length>50?'…':'');
    const titleEl = document.getElementById('orch-session-title');
    if (titleEl) titleEl.textContent = AIORCH.sessionTitle;
  }

  // Show thinking badge
  const thinkBadge = document.getElementById('orch-think-badge');
  if (thinkBadge) thinkBadge.style.display = 'inline-flex';

  // Log action
  _orchLog('user_message', prompt);

  try {
    let responseText = '';
    let enrichData = null;

    // If IOC detected, run enrichment pipeline first
    if (detectedIOC && iocType && ['ip','domain','url','md5','sha1','sha256','sha512'].includes(iocType)) {
      _orchLog('ioc_detected', `${iocType}: ${detectedIOC}`);

      // Show "gathering intel" status — explicitly state which sources are active vs missing key
      const srcStatus = [
        AIORCH.apiKeys.virustotal ? '🟢 VirusTotal' : '⬜ VirusTotal (no key)',
        (iocType === 'ip' || iocType === 'domain')
          ? (AIORCH.apiKeys.abuseipdb ? '🟢 AbuseIPDB' : '⬜ AbuseIPDB (no key)') : null,
        iocType === 'ip'
          ? (AIORCH.apiKeys.shodan ? '🟢 Shodan' : '⬜ Shodan (no key)') : null,
        '🟢 OTX (public)',   // OTX general endpoint requires no key
      ].filter(Boolean).join(' · ');

      const gatherMsg = document.createElement('div');
      gatherMsg.id = 'enrich-gathering-' + Date.now();
      gatherMsg.className = 'p19-msg p19-msg--assistant';
      gatherMsg.innerHTML = `<div class="p19-msg__avatar" style="background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.2);color:var(--p19-purple)"><i class="fas fa-robot"></i></div>
        <div class="p19-msg__bubble">
          <div style="font-size:.84em;color:var(--p19-t3);margin-bottom:4px"><i class="fas fa-circle-notch fa-spin" style="margin-right:6px;color:var(--p19-cyan)"></i><strong style="color:var(--p19-t2)">Querying threat intelligence sources…</strong></div>
          <div style="font-size:.76em;color:var(--p19-t4);margin-top:2px">${srcStatus}</div>
          <div style="font-size:.72em;color:var(--p19-t4);margin-top:4px">IOC: <code style="color:var(--p19-cyan)">${_e(detectedIOC)}</code> · Type: <strong style="color:var(--p19-t2)">${iocType.toUpperCase()}</strong></div>
        </div>`;
      const msgContainer = document.getElementById('orch-messages');
      if (msgContainer) { msgContainer.appendChild(gatherMsg); msgContainer.scrollTop = msgContainer.scrollHeight; }

      // Run all enrichment sources in parallel — blocking until all resolve/reject
      enrichData = await _orchEnrichIOC(detectedIOC, iocType);
      const enrichContext = _buildEnrichContext(enrichData, detectedIOC, iocType);

      // Remove gathering msg — replace with live results card immediately
      gatherMsg.remove();

      // Feed enriched context to AI
      const enrichedPrompt = `User asked: "${prompt}"\n\nMulti-source intelligence gathered:\n${enrichContext}\n\nProvide a comprehensive threat analysis based on this intelligence data. Include a verdict (MALICIOUS/SUSPICIOUS/CLEAN), threat actor attribution if possible, and recommended SOC actions.`;

      responseText = await _callAI([
        ...AIORCH.messages.slice(-4).map(m=>({role:m.role, content:m.content})),
        {role:'user', content: enrichedPrompt}
      ], detectedIOC);
    } else {
      // Regular AI query
      responseText = await _callAI(
        AIORCH.messages.slice(-6).map(m=>({role:m.role, content:m.content})),
        null
      );
    }

    // Remove typing indicator
    document.getElementById(typingId)?.remove();

    // Add assistant response
    AIORCH.messages.push({ role:'assistant', content: responseText, ts: Date.now() });
    _orchAddMsg('assistant', responseText, detectedIOC, iocType, enrichData);

    // Log completion
    _orchLog('ai_response', `${responseText.length} chars, IOC: ${detectedIOC||'none'}`);

  } catch (err) {
    document.getElementById(typingId)?.remove();
    const errMsg = `⚠️ **AI Error**: ${err.message}\n\nFalling back to local analysis…\n\n${_localAnalysis(prompt)}`;
    AIORCH.messages.push({ role:'assistant', content: errMsg, ts: Date.now() });
    _orchAddMsg('assistant', errMsg);
    _orchLog('error', err.message, 'error');
  } finally {
    AIORCH.isThinking = false;
    if (thinkBadge) thinkBadge.style.display = 'none';
    const sendBtn = document.getElementById('orch-send-btn');
    if (sendBtn) sendBtn.disabled = false;
  }
}

async function _callAI(messages, ioc) {
  const provider = AIORCH.aiProvider;

  // Priority 1: OpenAI (if key available)
  if (AIORCH.apiKeys.openai && (provider === 'openai' || provider === 'platform')) {
    try {
      _orchLog('ai_call', `OpenAI GPT-4o: ${messages.length} messages`);
      return await _callOpenAI(messages);
    } catch(err) {
      console.warn('[AI Orch] OpenAI failed:', err.message);
      _orchLog('ai_fallback', `OpenAI failed: ${err.message}. Trying Claude…`, 'warning');
    }
  }

  // Priority 2: Claude (if key available)
  if (AIORCH.apiKeys.claude && (provider === 'claude' || provider === 'openai' || provider === 'platform')) {
    try {
      _orchLog('ai_call', `Claude 3.5 Sonnet: ${messages.length} messages`);
      return await _callClaude(messages);
    } catch(err) {
      console.warn('[AI Orch] Claude failed:', err.message);
      _orchLog('ai_fallback', `Claude failed: ${err.message}. Trying platform…`, 'warning');
    }
  }

  // Priority 3: Platform backend AI
  try {
    const platformResult = await _callPlatformAI(messages);
    if (platformResult && !platformResult.includes('unavailable')) return platformResult;
  } catch(err) {
    console.warn('[AI Orch] Platform AI failed:', err.message);
  }

  // Final fallback: local analysis
  return _localAnalysis(messages[messages.length-1]?.content || '');
}

/* ═══════════════════════════════════════════════════════
   IOC ENRICHMENT PIPELINE
   Executes synchronously (blocking) with Promise.allSettled.
   All sources run in parallel; results are aggregated into
   a single object before returning. No background-only tasks.
   Keys are read from AIORCH.apiKeys (refreshed from localStorage
   by _orchRefreshKeys() before each invocation).
═══════════════════════════════════════════════════════ */
async function _orchEnrichIOC(value, type) {
  // Keys were refreshed by _orchRefreshKeys() in _orchSendMessage
  const results = {
    _meta: {
      ioc:       value,
      type:      type,
      queriedAt: new Date().toISOString(),
      keyStatus: {
        virustotal: !!AIORCH.apiKeys.virustotal ? 'configured' : 'missing_api_key',
        abuseipdb:  !!AIORCH.apiKeys.abuseipdb  ? 'configured' : 'missing_api_key',
        shodan:     !!AIORCH.apiKeys.shodan      ? 'configured' : 'missing_api_key',
        otx:        'public', // OTX /general endpoint is unauthenticated
      }
    }
  };
  const tasks = [];

  // ── VirusTotal ──────────────────────────────────────────────
  if (AIORCH.apiKeys.virustotal) {
    tasks.push(_vtLookup(value, type)
      .then(r  => { results.virustotal = r; })
      .catch(e => { results.virustotal = { error: e.message, source: 'virustotal' }; }));
  } else {
    results.virustotal = { notConfigured: true, status: 'missing_api_key',
      hint: 'Add VirusTotal API key in Settings → Threat Feeds' };
  }

  // ── AbuseIPDB — IP and domain ────────────────────────────────
  if (type === 'ip' || type === 'domain') {
    if (AIORCH.apiKeys.abuseipdb) {
      tasks.push(_abuseIPDBLookup(value)
        .then(r  => { results.abuseipdb = r; })
        .catch(e => { results.abuseipdb = { error: e.message, source: 'abuseipdb' }; }));
    } else {
      results.abuseipdb = { notConfigured: true, status: 'missing_api_key',
        hint: 'Add AbuseIPDB API key in Settings → Threat Feeds' };
    }
  }

  // ── Shodan — IP only ─────────────────────────────────────────
  if (type === 'ip') {
    if (AIORCH.apiKeys.shodan) {
      tasks.push(_shodanLookup(value)
        .then(r  => { results.shodan = r; })
        .catch(e => { results.shodan = { error: e.message, source: 'shodan' }; }));
    } else {
      results.shodan = { notConfigured: true, status: 'missing_api_key',
        hint: 'Add Shodan API key in Settings → Threat Feeds' };
    }
  }

  // ── AlienVault OTX — public endpoint (no key required) ───────
  // OTX /indicators/{type}/{value}/general is publicly accessible.
  // Key is sent if available for higher rate limits only.
  tasks.push(_otxLookup(value, type)
    .then(r  => { results.otx = r; })
    .catch(e => { results.otx = { error: e.message, source: 'otx' }; }));

  // ── Wait for all in parallel — blocking, synchronous result ──
  await Promise.allSettled(tasks);
  return results;
}

async function _vtLookup(value, type) {
  let subPath = '';
  if (type==='ip')     subPath = `/ip_addresses/${value}`;
  else if (type==='domain') subPath = `/domains/${value}`;
  else if (['md5','sha1','sha256','sha512'].includes(type)) subPath = `/files/${value}`;
  else if (type==='url') {
    const id = btoa(value).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    subPath = `/urls/${id}`;
  }
  if (!subPath) return { error: 'Unsupported IOC type for VirusTotal' };

  // SECURITY: VT API key is injected server-side by /api/proxy/vt (Vercel) or
  // proxy-server.js (local dev). Never send keys from the frontend.
  let r;
  try {
    r = await fetch(`/proxy/vt${subPath}`, {
      signal: AbortSignal.timeout ? AbortSignal.timeout(15000) : undefined,
    });
  } catch (netErr) {
    throw new Error(`VirusTotal: network error — ${netErr.message}`);
  }

  // Read body as text first — proxy may return HTML error page
  const text = await r.text().catch(() => '');

  // Parse as JSON safely
  let d;
  try {
    d = JSON.parse(text);
  } catch (_) {
    // Non-JSON (HTML 401/403 from VT or proxy) → treat as missing key
    if (r.status === 401 || r.status === 403) {
      throw new Error('VirusTotal: missing_api_key — set VT_API_KEY in environment variables');
    }
    throw new Error(`VirusTotal: invalid response (HTTP ${r.status}) — ${text.slice(0, 100)}`);
  }

  // Handle missing_api_key proxy response
  if (d.error === 'missing_api_key' || d.status === 'missing_api_key') {
    throw new Error('VirusTotal: missing_api_key — set VT_API_KEY in environment variables');
  }
  // Handle VT API-level errors
  if (d.error?.code === 'AuthenticationRequiredError' || d.error?.code === 'WrongCredentialsError') {
    throw new Error(`VirusTotal: authentication failed — ${d.error.message || 'invalid API key'}`);
  }
  if (!r.ok && !d.data) throw new Error(`VT: HTTP ${r.status} — ${d.error?.message || text.slice(0, 100)}`);

  const stats = d.data?.attributes?.last_analysis_stats || {};
  const engines = d.data?.attributes?.last_analysis_results || {};
  const maliciousEngines = Object.entries(engines)
    .filter(([,v])=>v.category==='malicious')
    .map(([name,v])=>({name, result:v.result}))
    .slice(0,10);
  return {
    malicious:       stats.malicious   || 0,
    suspicious:      stats.suspicious  || 0,
    harmless:        stats.harmless    || 0,
    undetected:      stats.undetected  || 0,
    total:           Object.values(stats).reduce((s,v)=>s+(v||0), 0),
    reputation:      d.data?.attributes?.reputation || 0,
    categories:      d.data?.attributes?.categories || {},
    country:         d.data?.attributes?.country || '',
    as_owner:        d.data?.attributes?.as_owner || '',
    maliciousEngines,
    tags:            d.data?.attributes?.tags || [],
    lastAnalysisDate:d.data?.attributes?.last_analysis_date || null,
  };
}

async function _abuseIPDBLookup(ip) {
  // SECURITY: AbuseIPDB API key is injected server-side by /api/proxy/abuseipdb (Vercel).
  let r;
  try {
    r = await fetch(`/proxy/abuseipdb/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`, {
      signal: AbortSignal.timeout ? AbortSignal.timeout(15000) : undefined,
    });
  } catch (netErr) {
    throw new Error(`AbuseIPDB: network error — ${netErr.message}`);
  }
  const text = await r.text().catch(() => '');
  let d;
  try { d = JSON.parse(text); } catch (_) {
    if (r.status === 401 || r.status === 403) throw new Error('AbuseIPDB: missing_api_key — set ABUSEIPDB_API_KEY in environment variables');
    throw new Error(`AbuseIPDB: invalid response (HTTP ${r.status})`);
  }
  // Handle missing_api_key proxy response
  if (d.error === 'missing_api_key' || d.status === 'missing_api_key') {
    throw new Error('AbuseIPDB: missing_api_key — set ABUSEIPDB_API_KEY in environment variables');
  }
  if (!r.ok && !d.data) throw new Error(`AbuseIPDB: HTTP ${r.status} — ${d.errors?.[0]?.detail || text.slice(0,100)}`);
  return {
    abuseScore:    d.data?.abuseConfidenceScore || 0,
    totalReports:  d.data?.totalReports || 0,
    countryCode:   d.data?.countryCode || '',
    isp:           d.data?.isp || '',
    domain:        d.data?.domain || '',
    usageType:     d.data?.usageType || '',
    isWhitelisted: d.data?.isWhitelisted || false,
    lastReportedAt:d.data?.lastReportedAt || null,
  };
}

async function _shodanLookup(ip) {
  // SECURITY: Shodan API key is NEVER sent in the URL.
  // The Vercel /api/proxy/shodan serverless function injects the key from
  // the SHODAN_API_KEY environment variable server-side.
  // If running via local proxy-server.js, key is stripped from client params and re-added.
  let r;
  try {
    r = await fetch(`/proxy/shodan/shodan/host/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout ? AbortSignal.timeout(15000) : undefined,
    });
  } catch (netErr) {
    throw new Error(`Shodan: network error — ${netErr.message}`);
  }
  const text = await r.text().catch(() => '');
  let d;
  try { d = JSON.parse(text); } catch (_) {
    if (r.status === 401 || r.status === 403) throw new Error('Shodan: missing_api_key — set SHODAN_API_KEY in environment variables');
    if (r.status === 404) return { country:'', org:'No data', os:'', ports:[], vulns:[], hostnames:[], notFound:true };
    throw new Error(`Shodan: invalid response (HTTP ${r.status})`);
  }
  // Handle missing_api_key response from proxy
  if (d.status === 'missing_api_key' || d.error === 'missing_api_key') {
    throw new Error('Shodan: missing_api_key — set SHODAN_API_KEY in environment variables');
  }
  if (d.error === 'Not Found' || r.status === 404) {
    return { country:'', org:'No Shodan data for this IP', os:'', ports:[], vulns:[], hostnames:[], notFound:true };
  }
  if (!r.ok && !d.country_name) throw new Error(`Shodan: HTTP ${r.status} — ${d.error || text.slice(0,100)}`);
  return {
    country:  d.country_name || '',
    org:      d.org          || '',
    os:       d.os           || '',
    ports:    (d.ports||[]).slice(0,10),
    vulns:    Object.keys(d.vulns||{}).slice(0,5),
    hostnames: (d.hostnames||[]).slice(0,5),
  };
}

async function _otxLookup(value, type) {
  const key = AIORCH.apiKeys.otx; // Optional — OTX /general is public

  // ── Input validation before sending any HTTP request ────────
  // OTX API returns HTTP 400 for:
  //   • IPv4 with CIDR notation (e.g. "1.2.3.4/24")
  //   • Private/loopback IPs (10.x, 192.168.x, 127.x)
  //   • Hash types other than md5/sha1/sha256 submitted as 'file'
  //   • Empty or whitespace-only values
  // We catch these here to avoid a 400 that shows as ERROR in the UI.

  const v = String(value || '').trim();
  if (!v) throw new Error('OTX: empty indicator value');

  // Strip CIDR notation for IP addresses — OTX wants a plain IP
  let cleanValue = v;
  if (type === 'ip') {
    // Reject CIDR ranges — OTX /IPv4 endpoint requires a single IP
    if (v.includes('/')) {
      throw new Error(`OTX: CIDR ranges not supported (got "${v}") — provide a single IP address`);
    }
    // Validate it's a real routable IPv4 (OTX rejects private/reserved ranges)
    const parts = v.split('.');
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      throw new Error(`OTX: invalid IPv4 address "${v}"`);
    }
    // Note: OTX does accept private-range IPs for reputation queries
    // (returns empty results) — only block completely invalid ones above.
  }

  if (type === 'url') {
    // URL must be encoded properly and must start with http(s)
    if (!/^https?:\/\//i.test(v)) {
      throw new Error(`OTX: URL must start with http:// or https:// (got "${v.slice(0,50)}")`);
    }
  }

  if (type === 'domain') {
    // Basic domain validation
    if (!/^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,250}$/.test(v)) {
      throw new Error(`OTX: invalid domain format "${v.slice(0,50)}"`);
    }
  }

  // Map internal type names → OTX endpoint type segment
  const OTX_TYPE_MAP = {
    ip:     'IPv4',
    domain: 'domain',
    url:    'url',      // OTX uses lowercase 'url' not 'URL'
    md5:    'file',
    sha1:   'file',
    sha256: 'file',
    sha512: 'file',
  };
  const otxType = OTX_TYPE_MAP[type] || 'general';

  // For file hashes, OTX uses /file/{hash} not /file/general
  const endpointValue = (type === 'url')
    ? encodeURIComponent(cleanValue)  // URL-encode full URL
    : encodeURIComponent(cleanValue);

  const proxyUrl = `/proxy/otx/indicators/${otxType}/${endpointValue}/general`;

  let r;
  try {
    r = await fetch(proxyUrl, { signal: AbortSignal.timeout ? AbortSignal.timeout(12000) : undefined });
  } catch (netErr) {
    throw new Error(`OTX: network error — ${netErr.message}`);
  }

  if (r.status === 400) {
    // OTX returns 400 for unsupported indicator types/formats
    let detail = '';
    try {
      const txt = await r.text();
      const j = JSON.parse(txt);
      detail = j.detail || j.error || '';
    } catch {}
    throw new Error(`OTX: indicator format rejected by API${detail ? ': ' + detail : ''} — value="${v}", type="${otxType}"`);
  }
  if (r.status === 404) {
    // OTX returns 404 for unknown indicators (legitimate — means no data)
    return {
      pulse_count: 0, threat_score: 'public', indicator: v, reputation: 0,
      tags: [], threatActors: [], malware_families: [], pulses: [],
      keyUsed: !!key, notFound: true,
    };
  }
  if (!r.ok) throw new Error(`OTX: HTTP ${r.status}`);

  // Read body as text first — proxy might return HTML error on some network issues
  const bodyText = await r.text().catch(() => '');
  let d;
  try {
    d = JSON.parse(bodyText);
  } catch (parseErr) {
    // If we got HTML (e.g. Cloudflare block or proxy error), give a clear message
    const preview = bodyText.slice(0, 80).replace(/[\r\n]+/g, ' ');
    if (bodyText.trimStart().startsWith('<')) {
      throw new Error(`OTX: proxy returned HTML instead of JSON — possible rate limit or network issue. Preview: ${preview}`);
    }
    throw new Error(`OTX: invalid JSON response — ${parseErr.message}. Preview: ${preview}`);
  }

  const pulses = d.pulse_info?.pulses || [];
  const tags = [...new Set(pulses.flatMap(p => p.tags || []))].slice(0, 8);
  const threatActors = [...new Set(pulses.map(p => p.author?.username).filter(Boolean))].slice(0, 5);
  return {
    pulse_count:     d.pulse_info?.count || 0,
    threat_score:    d.base_indicator?.access_type || 'public',
    indicator:       d.indicator,
    reputation:      d.reputation || 0,
    tags,
    threatActors,
    malware_families: (d.malware_families || []).slice(0, 5).map(m => m.display_name || m),
    pulses:          pulses.slice(0, 5).map(p => ({ name: p.name, modified: p.modified, author: p.author?.username })),
    keyUsed:         !!key,
  };
}

function _buildEnrichContext(data, value, type) {
  let ctx = `IOC: ${value} (${type.toUpperCase()})\n`;
  // Include key status metadata in context
  if (data._meta?.keyStatus) {
    const ks = data._meta.keyStatus;
    ctx += `Key status — VirusTotal: ${ks.virustotal}, AbuseIPDB: ${ks.abuseipdb}, Shodan: ${ks.shodan}, OTX: ${ks.otx}\n`;
  }
  ctx += '\n';
  let sourcesUsed = 0;

  // VirusTotal
  if (data.virustotal && !data.virustotal.error && !data.virustotal.notConfigured) {
    const vt = data.virustotal;
    const verdict = vt.malicious > 5 ? 'MALICIOUS' : vt.malicious > 0 ? 'SUSPICIOUS' : 'CLEAN';
    ctx += `VirusTotal [LIVE]: ${verdict} — ${vt.malicious}/${vt.total} engines flagged as malicious, ${vt.suspicious} suspicious. Reputation: ${vt.reputation}. Country: ${vt.country||'Unknown'}. ASN: ${vt.as_owner||'Unknown'}.`;
    if (vt.maliciousEngines?.length) ctx += ` Detected by: ${vt.maliciousEngines.map(e=>e.name).join(', ')}.`;
    ctx += '\n';
    sourcesUsed++;
  } else if (data.virustotal?.error) {
    ctx += `VirusTotal [ERROR]: ${data.virustotal.error}\n`;
  } else if (data.virustotal?.notConfigured) {
    ctx += `VirusTotal [missing_api_key]: No key configured — add in Settings → Threat Feeds. Manual check: https://www.virustotal.com/gui/${type==='ip'?'ip-address':type==='domain'?'domain':'file'}/${value}\n`;
  }

  // AbuseIPDB
  if (data.abuseipdb && !data.abuseipdb.error && !data.abuseipdb.notConfigured) {
    const ab = data.abuseipdb;
    ctx += `AbuseIPDB [LIVE]: Abuse confidence ${ab.abuseScore}/100, ${ab.totalReports} reports. ISP: ${ab.isp||'Unknown'}. Country: ${ab.countryCode||'Unknown'}. Usage: ${ab.usageType||'unknown'}. Whitelisted: ${ab.isWhitelisted?'yes':'no'}.\n`;
    sourcesUsed++;
  } else if (data.abuseipdb?.error) {
    ctx += `AbuseIPDB [ERROR]: ${data.abuseipdb.error}\n`;
  } else if (data.abuseipdb?.notConfigured) {
    ctx += `AbuseIPDB [missing_api_key]: No key configured — add in Settings → Threat Feeds.\n`;
  }

  // Shodan
  if (data.shodan && !data.shodan.error && !data.shodan.notConfigured) {
    const sh = data.shodan;
    ctx += `Shodan [LIVE]: Org: ${sh.org||'Unknown'}, Country: ${sh.country||'Unknown'}, OS: ${sh.os||'unknown'}. Open ports: ${sh.ports.join(', ')||'none'}. CVEs on host: ${sh.vulns.join(', ')||'none'}. Hostnames: ${sh.hostnames.join(', ')||'none'}.\n`;
    sourcesUsed++;
  } else if (data.shodan?.error) {
    ctx += `Shodan [ERROR]: ${data.shodan.error}\n`;
  } else if (data.shodan?.notConfigured) {
    ctx += `Shodan [missing_api_key]: No key configured — add in Settings → Threat Feeds.\n`;
  }

  // AlienVault OTX (always runs — public endpoint)
  if (data.otx && !data.otx.error) {
    const otx = data.otx;
    ctx += `AlienVault OTX [LIVE${otx.keyUsed ? '+KEY' : '/PUBLIC'}]: ${otx.pulse_count} threat pulses, reputation ${otx.reputation}. Malware families: ${otx.malware_families?.join(', ')||'none'}. Tags: ${otx.tags?.slice(0,5).join(', ')||'none'}.`;
    if (otx.pulses?.length) ctx += ` Recent pulses: ${otx.pulses.map(p=>p.name).join('; ')}.`;
    ctx += '\n';
    sourcesUsed++;
  } else if (data.otx?.error) {
    ctx += `AlienVault OTX [ERROR]: ${data.otx.error}\n`;
  }

  if (sourcesUsed === 0) {
    ctx += `\nNote: No live threat intelligence data available. OTX public endpoint may have failed. Add VirusTotal, AbuseIPDB, and Shodan API keys in Settings → Threat Feeds for full enrichment coverage.`;
  }
  return ctx;
}

// Render enrichment data as a visual card in the chat
// Shows all 4 source cards: live data, error, or "not configured"
function _renderEnrichCard(data, value, type) {
  // ── Verdict badge ────────────────────────────────────────────
  const vt  = data.virustotal;
  const ab  = data.abuseipdb;
  const sh  = data.shodan;
  const otx = data.otx;

  // Compute overall verdict from available data
  let verdictLevel = 'UNKNOWN';
  let verdictColor = '#64748b';
  let verdictIcon  = 'fa-question-circle';

  if (vt && !vt.error && !vt.notConfigured) {
    if (vt.malicious > 10)      { verdictLevel = 'MALICIOUS';  verdictColor = '#ef4444'; verdictIcon = 'fa-skull-crossbones'; }
    else if (vt.malicious > 2)  { verdictLevel = 'SUSPICIOUS'; verdictColor = '#f97316'; verdictIcon = 'fa-exclamation-triangle'; }
    else if (vt.malicious > 0)  { verdictLevel = 'LOW RISK';   verdictColor = '#f59e0b'; verdictIcon = 'fa-exclamation-circle'; }
    else                         { verdictLevel = 'CLEAN';      verdictColor = '#22c55e'; verdictIcon = 'fa-check-circle'; }
  } else if (ab && !ab.error && !ab.notConfigured) {
    if (ab.abuseScore > 75)     { verdictLevel = 'MALICIOUS';  verdictColor = '#ef4444'; verdictIcon = 'fa-skull-crossbones'; }
    else if (ab.abuseScore > 25) { verdictLevel = 'SUSPICIOUS'; verdictColor = '#f97316'; verdictIcon = 'fa-exclamation-triangle'; }
    else                         { verdictLevel = 'CLEAN';      verdictColor = '#22c55e'; verdictIcon = 'fa-check-circle'; }
  } else if (otx && !otx.error) {
    if (otx.pulse_count > 10)   { verdictLevel = 'SUSPICIOUS'; verdictColor = '#f97316'; verdictIcon = 'fa-exclamation-triangle'; }
    else if (otx.pulse_count > 0){ verdictLevel = 'MONITORED'; verdictColor = '#f59e0b'; verdictIcon = 'fa-eye'; }
    else                         { verdictLevel = 'NO HITS';    verdictColor = '#22c55e'; verdictIcon = 'fa-check-circle'; }
  }

  // ── Source status dots ───────────────────────────────────────
  const dot = (name, ok, errMsg) => {
    const color = ok ? '#22c55e' : errMsg ? '#ef4444' : '#475569';
    const title = ok ? 'Live data' : errMsg || 'Not configured';
    return `<span title="${_e(title)}" style="display:inline-flex;align-items:center;gap:3px;font-size:11px;color:${color};font-weight:600;">
      <span style="width:6px;height:6px;border-radius:50%;background:${color};display:inline-block;"></span>${name}</span>`;
  };

  const vtOk  = vt  && !vt.error  && !vt.notConfigured;
  const abOk  = ab  && !ab.error  && !ab.notConfigured;
  const shOk  = sh  && !sh.error  && !sh.notConfigured && !sh.notFound;
  const otxOk = otx && !otx.error;

  const statusRow = [
    dot('VT',    vtOk,  vt?.error),
    dot('AIPDB', abOk,  ab?.error),
    type === 'ip' ? dot('Shodan', shOk, sh?.error) : null,
    dot('OTX',   otxOk, otx?.error),
  ].filter(Boolean).join('<span style="color:#334155;padding:0 4px">·</span>');

  // ── Source cards ─────────────────────────────────────────────
  const card = (title, icon, accentColor, content, footerLink) => `
    <div style="background:rgba(15,23,42,0.6);border:1px solid rgba(255,255,255,0.07);border-radius:12px;padding:14px;flex:1;min-width:190px;max-width:260px;display:flex;flex-direction:column;gap:6px;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
        <div style="width:30px;height:30px;background:${accentColor}20;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
          <i class="fas ${icon}" style="color:${accentColor};font-size:13px;"></i>
        </div>
        <span style="font-weight:700;font-size:13px;color:#e2e8f0;">${title}</span>
      </div>
      <div style="flex:1;font-size:12px;line-height:1.65;">${content}</div>
      ${footerLink ? `<div style="padding-top:6px;border-top:1px solid rgba(255,255,255,0.06);">${footerLink}</div>` : ''}
    </div>`;

  const kv = (label, val, valColor) =>
    `<div style="display:flex;justify-content:space-between;align-items:baseline;padding:2px 0;border-bottom:1px solid rgba(255,255,255,0.04);">
      <span style="color:#64748b;">${label}</span>
      <strong style="color:${valColor||'#cbd5e1'};margin-left:8px;text-align:right;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${val}</strong>
    </div>`;

  const errContent = (msg) => `<span style="color:#f87171;font-size:11px;">${_e(msg)}</span>`;
  const missingContent = (name) => `<div style="color:#475569;font-size:11px;">Not configured.<br>Add ${name} API key in<br><strong style="color:#94a3b8;">Settings → Threat Feeds</strong></div>`;

  const extLink = (href, label, color) =>
    `<a href="${href}" target="_blank" rel="noopener" style="color:${color||'#22d3ee'};font-size:11px;text-decoration:none;"><i class="fas fa-external-link-alt" style="margin-right:3px;font-size:9px;"></i>${label}</a>`;

  let cards = '';

  // VirusTotal
  if (vt?.notConfigured) {
    cards += card('VirusTotal', 'fa-virus', '#3b82f6', missingContent('VirusTotal'),
      extLink(`https://www.virustotal.com/gui/${type==='ip'?'ip-address':type==='domain'?'domain':'file'}/${value}`, 'Check manually →', '#3b82f6'));
  } else if (vt?.error) {
    cards += card('VirusTotal', 'fa-virus', '#ef4444',
      errContent(vt.error),
      extLink(`https://www.virustotal.com/gui/${type==='ip'?'ip-address':type==='domain'?'domain':'file'}/${value}`, 'Check manually →', '#3b82f6'));
  } else if (vt) {
    const pct  = vt.total > 0 ? Math.round(vt.malicious / vt.total * 100) : 0;
    const vc   = vt.malicious > 10 ? '#ef4444' : vt.malicious > 2 ? '#f97316' : vt.malicious > 0 ? '#f59e0b' : '#22c55e';
    const verdict = vt.malicious > 10 ? 'MALICIOUS' : vt.malicious > 2 ? 'SUSPICIOUS' : vt.malicious > 0 ? 'LOW RISK' : 'CLEAN';
    const vtContent = [
      kv('Detection', `${vt.malicious}/${vt.total} (${pct}%)`, vc),
      kv('Suspicious', vt.suspicious, vt.suspicious > 0 ? '#f59e0b' : '#22c55e'),
      vt.country ? kv('Country', vt.country) : '',
      vt.as_owner ? kv('ASN / Org', vt.as_owner.slice(0, 25)) : '',
      kv('Reputation', vt.reputation >= 0 ? `+${vt.reputation}` : `${vt.reputation}`, vt.reputation < 0 ? '#ef4444' : '#22c55e'),
    ].join('');
    const engineList = vt.maliciousEngines?.length
      ? `<div style="margin-top:6px;font-size:10px;color:#ef4444;">Flagged by: ${vt.maliciousEngines.slice(0,4).map(e=>e.name).join(', ')}</div>` : '';
    cards += card(`VirusTotal <span style="font-size:10px;font-weight:800;color:${vc};background:${vc}20;padding:1px 6px;border-radius:4px;margin-left:4px;">${verdict}</span>`,
      'fa-virus', '#3b82f6', vtContent + engineList,
      extLink(`https://www.virustotal.com/gui/${type==='ip'?'ip-address':type==='domain'?'domain':'file'}/${value}`, 'Full Report →', '#3b82f6'));
  }

  // AbuseIPDB
  if (ab?.notConfigured) {
    cards += card('AbuseIPDB', 'fa-shield-alt', '#ef4444', missingContent('AbuseIPDB'),
      type === 'ip' ? extLink(`https://www.abuseipdb.com/check/${value}`, 'Check manually →', '#ef4444') : '');
  } else if (ab?.error) {
    cards += card('AbuseIPDB', 'fa-shield-alt', '#ef4444', errContent(ab.error),
      type === 'ip' ? extLink(`https://www.abuseipdb.com/check/${value}`, 'Check manually →', '#ef4444') : '');
  } else if (ab) {
    const rc = ab.abuseScore > 75 ? '#ef4444' : ab.abuseScore > 25 ? '#f97316' : '#22c55e';
    const abContent = [
      kv('Abuse Score', `${ab.abuseScore}%`, rc),
      kv('Reports', ab.totalReports, ab.totalReports > 0 ? '#f59e0b' : '#22c55e'),
      ab.countryCode ? kv('Country', ab.countryCode) : '',
      ab.isp ? kv('ISP', ab.isp.slice(0, 25)) : '',
      ab.usageType ? kv('Usage Type', ab.usageType) : '',
    ].join('');
    cards += card(`AbuseIPDB <span style="font-size:10px;font-weight:800;color:${rc};background:${rc}20;padding:1px 6px;border-radius:4px;margin-left:4px;">${ab.abuseScore}% RISK</span>`,
      'fa-shield-alt', '#ef4444', abContent,
      extLink(`https://www.abuseipdb.com/check/${value}`, 'Full Report →', '#ef4444'));
  }

  // Shodan (IP only)
  if (type === 'ip') {
    if (sh?.notConfigured) {
      cards += card('Shodan', 'fa-server', '#f97316', missingContent('Shodan'),
        extLink(`https://www.shodan.io/host/${value}`, 'Check manually →', '#f97316'));
    } else if (sh?.error) {
      cards += card('Shodan', 'fa-server', '#ef4444', errContent(sh.error),
        extLink(`https://www.shodan.io/host/${value}`, 'Check manually →', '#f97316'));
    } else if (sh?.notFound) {
      cards += card('Shodan', 'fa-server', '#64748b',
        `<span style="color:#475569;font-size:12px;">No Shodan data for this IP.<br>Host may not be internet-facing or scanned yet.</span>`,
        extLink(`https://www.shodan.io/host/${value}`, 'Check manually →', '#f97316'));
    } else if (sh) {
      const shContent = [
        sh.org ? kv('Org', sh.org.slice(0, 25)) : '',
        sh.country ? kv('Country', sh.country) : '',
        kv('Open Ports', sh.ports?.length ? sh.ports.slice(0,6).join(', ') : 'none', sh.ports?.length ? '#f97316' : '#22c55e'),
        sh.os ? kv('OS', sh.os) : '',
        sh.vulns?.length ? kv('CVEs on host', sh.vulns.slice(0,3).join(', '), '#ef4444') : kv('CVEs on host', 'None known', '#22c55e'),
      ].join('');
      const vulnBadge = sh.vulns?.length
        ? `<span style="font-size:10px;font-weight:800;color:#ef4444;background:#ef444420;padding:1px 6px;border-radius:4px;margin-left:4px;">${sh.vulns.length} VULNS</span>` : '';
      cards += card(`Shodan${vulnBadge}`, 'fa-server', '#f97316', shContent,
        extLink(`https://www.shodan.io/host/${value}`, 'Full Report →', '#f97316'));
    }
  }

  // OTX
  if (otx?.error) {
    cards += card('AlienVault OTX', 'fa-satellite', '#a855f7', errContent(otx.error),
      extLink(`https://otx.alienvault.com/indicator/${type==='ip'?'ip':type==='domain'?'domain':'file'}/${encodeURIComponent(value)}`, 'Check manually →', '#a855f7'));
  } else if (otx) {
    const pulseColor = otx.pulse_count > 10 ? '#ef4444' : otx.pulse_count > 0 ? '#f59e0b' : '#22c55e';
    const otxContent = [
      kv('Threat Pulses', otx.pulse_count, pulseColor),
      kv('Reputation', otx.reputation < 0 ? otx.reputation : `+${otx.reputation}`, otx.reputation < 0 ? '#ef4444' : '#22c55e'),
      otx.malware_families?.length ? kv('Malware', otx.malware_families.slice(0,2).join(', '), '#a855f7') : '',
      otx.tags?.length ? kv('Tags', otx.tags.slice(0,3).join(', ')) : '',
    ].join('');
    const pulseSample = otx.pulses?.length
      ? `<div style="margin-top:6px;font-size:10px;color:#94a3b8;">Latest: "${_e(otx.pulses[0].name?.slice(0,40))}"</div>` : '';
    const badge = otx.pulse_count > 0
      ? `<span style="font-size:10px;font-weight:800;color:${pulseColor};background:${pulseColor}20;padding:1px 6px;border-radius:4px;margin-left:4px;">${otx.pulse_count} PULSES</span>` : '';
    cards += card(`OTX${badge}`, 'fa-satellite', '#a855f7', otxContent + pulseSample,
      extLink(`https://otx.alienvault.com/indicator/${type==='ip'?'ip':type==='domain'?'domain':'file'}/${encodeURIComponent(value)}`, 'Full Report →', '#a855f7'));
  }

  // ── Overall Summary Bar ──────────────────────────────────────
  const iocLabel = type === 'ip' ? '🌐 IP' : type === 'domain' ? '🔗 Domain' : type === 'url' ? '🔗 URL' : '🧬 Hash';

  return `
  <div style="background:linear-gradient(135deg,rgba(15,23,42,0.95),rgba(30,27,75,0.6));border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:16px 18px;margin:8px 0 12px;">

    <!-- Header: IOC + Verdict -->
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:12px;">
      <div style="display:flex;align-items:center;gap:8px;">
        <i class="fas fa-satellite-dish" style="color:#22d3ee;font-size:14px;"></i>
        <span style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#64748b;">Multi-Source Intel Report</span>
        <span style="font-size:12px;font-weight:700;color:#22d3ee;font-family:monospace;background:rgba(34,211,238,0.1);padding:2px 8px;border-radius:6px;">${iocLabel}: ${_e(value)}</span>
      </div>
      <div style="display:flex;align-items:center;gap:8px;">
        <i class="fas ${verdictIcon}" style="color:${verdictColor};font-size:14px;"></i>
        <span style="font-size:13px;font-weight:800;color:${verdictColor};">${verdictLevel}</span>
        <span style="font-size:10px;color:#475569;">${new Date().toLocaleTimeString()}</span>
      </div>
    </div>

    <!-- Source status dots -->
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid rgba(255,255,255,0.06);">
      ${statusRow}
    </div>

    <!-- Source cards grid -->
    <div style="display:flex;flex-wrap:wrap;gap:10px;">
      ${cards || `<div style="color:#475569;font-size:12px;padding:8px;">No enrichment data — add API keys in Settings → Threat Feeds for full analysis.</div>`}
    </div>

  </div>`;
}


/* ═══════════════════════════════════════════════════════
   MESSAGE RENDERING
═══════════════════════════════════════════════════════ */
function _orchAddMsg(role, content, ioc, iocType, enrichData) {
  const container = document.getElementById('orch-messages');
  if (!container) return;

  const div = document.createElement('div');
  div.className = `p19-msg p19-msg--${role}`;
  div.style.animation = 'p19-slideUp .2s ease';

  const avatarBg = role === 'assistant'
    ? 'background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.2);color:var(--p19-purple)'
    : 'background:rgba(34,211,238,.1);border:1px solid rgba(34,211,238,.2);color:var(--p19-cyan)';

  // Build enrichment card if we have data
  const enrichCard = (role === 'assistant' && enrichData && ioc && iocType)
    ? _renderEnrichCard(enrichData, ioc, iocType)
    : '';

  div.innerHTML = `
    <div class="p19-msg__avatar" style="${avatarBg}">
      <i class="fas ${role==='assistant'?'fa-robot':'fa-user'}"></i>
    </div>
    <div class="p19-msg__bubble">
      ${enrichCard}
      ${_formatMd(content)}
      ${ioc && iocType ? _orchIOCLinks(ioc, iocType) : ''}
      <div style="font-size:.68em;color:var(--p19-t4);margin-top:6px;text-align:right">${new Date().toLocaleTimeString()}</div>
    </div>
  `;

  container.appendChild(div);
  container.scrollTop = container.scrollHeight;

  // Hide suggestions after first user message
  if (role === 'user') {
    const sugg = document.getElementById('orch-suggestions');
    if (sugg) sugg.style.display = 'none';
  }
}

function _orchAddTyping(id) {
  const container = document.getElementById('orch-messages');
  if (!container) return;
  const div = document.createElement('div');
  div.id = id;
  div.className = 'p19-msg p19-msg--assistant';
  div.innerHTML = `
    <div class="p19-msg__avatar" style="background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.2);color:var(--p19-purple)">
      <i class="fas fa-robot"></i>
    </div>
    <div class="p19-msg__bubble">
      <div class="p19-typing">
        <span></span><span></span><span></span>
      </div>
    </div>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function _orchIOCLinks(ioc, type) {
  const links = [];
  if (['ip','domain','url','md5','sha1','sha256','sha512'].includes(type)) {
    const vtUrl = type==='ip' ? `https://www.virustotal.com/gui/ip-address/${ioc}` :
                  type==='domain' ? `https://www.virustotal.com/gui/domain/${ioc}` :
                  type==='url' ? `https://www.virustotal.com/gui/url/${btoa(ioc).replace(/=/g,'')}` :
                  `https://www.virustotal.com/gui/file/${ioc}`;
    links.push(`<a href="${vtUrl}" target="_blank" rel="noopener" style="color:var(--p19-blue);font-size:.78em;text-decoration:none">
      <i class="fas fa-external-link-alt" style="font-size:.7em;margin-right:2px"></i>VirusTotal</a>`);
  }
  if (type === 'ip') {
    links.push(`<a href="https://www.abuseipdb.com/check/${ioc}" target="_blank" rel="noopener" style="color:var(--p19-red);font-size:.78em;text-decoration:none">
      <i class="fas fa-external-link-alt" style="font-size:.7em;margin-right:2px"></i>AbuseIPDB</a>`);
    links.push(`<a href="https://www.shodan.io/host/${ioc}" target="_blank" rel="noopener" style="color:var(--p19-orange);font-size:.78em;text-decoration:none">
      <i class="fas fa-external-link-alt" style="font-size:.7em;margin-right:2px"></i>Shodan</a>`);
  }
  const otxType = type==='ip'?'ip':type==='domain'?'domain':type==='url'?'url':'file';
  links.push(`<a href="https://otx.alienvault.com/indicator/${otxType}/${encodeURIComponent(ioc)}" target="_blank" rel="noopener" style="color:var(--p19-purple);font-size:.78em;text-decoration:none">
    <i class="fas fa-external-link-alt" style="font-size:.7em;margin-right:2px"></i>OTX</a>`);

  if (!links.length) return '';
  return `
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:8px;padding-top:8px;border-top:1px solid var(--p19-border)">
    <span style="font-size:.74em;color:var(--p19-t4)">Investigate:</span>
    ${links.join('')}
  </div>`;
}

// ─── Markdown → HTML formatter ──────────────────────────────────
// CRITICAL: Process markdown FIRST (before HTML-escaping the rest),
// then escape any remaining raw HTML. This prevents the common bug
// where bold/italic/backtick markers get escaped before the regex runs.
function _formatMd(text) {
  if (!text) return '';

  // Step 1: Extract and protect code blocks (before any escaping)
  const codeBlocks = [];
  let safe = text
    // Fenced code blocks  ```...```
    .replace(/```([\s\S]*?)```/g, (_, code) => {
      const idx = codeBlocks.length;
      codeBlocks.push(`<pre style="background:rgba(0,0,0,.35);border:1px solid var(--p19-border);border-radius:8px;padding:10px 14px;font-family:'JetBrains Mono',monospace;font-size:.82em;overflow-x:auto;margin:8px 0;white-space:pre-wrap;">${_e(code.trim())}</pre>`);
      return `\x00CODE${idx}\x00`;
    })
    // Inline code  `...`
    .replace(/`([^`\n]+)`/g, (_, code) => {
      const idx = codeBlocks.length;
      codeBlocks.push(`<code style="background:rgba(0,0,0,.3);border:1px solid var(--p19-border);border-radius:3px;padding:1px 5px;font-family:'JetBrains Mono',monospace;font-size:.88em;color:#22d3ee;">${_e(code)}</code>`);
      return `\x00CODE${idx}\x00`;
    });

  // Step 2: Apply markdown transformations on the safe string
  safe = safe
    // Headers (## Verdict, ## Summary etc)
    .replace(/^#### (.+)$/gm, '<h5 style="margin:8px 0 3px;font-size:.85em;color:#a855f7;font-weight:700;">$1</h5>')
    .replace(/^### (.+)$/gm, '<h4 style="margin:10px 0 4px;font-size:.9em;color:#22d3ee;font-weight:700;border-bottom:1px solid rgba(34,211,238,.2);padding-bottom:3px;">$1</h4>')
    .replace(/^## (.+)$/gm, '<h3 style="margin:14px 0 6px;font-size:1em;color:#f1f5f9;font-weight:800;border-left:3px solid #3b82f6;padding-left:8px;">$1</h3>')
    .replace(/^# (.+)$/gm,  '<h2 style="margin:14px 0 6px;font-size:1.1em;color:#f1f5f9;font-weight:800;">$1</h2>')
    // Bold + italic (order matters)
    .replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
    .replace(/\*\*(.+?)\*\*/g, '<strong style="color:#f1f5f9;font-weight:700;">$1</strong>')
    .replace(/\*(.+?)\*/g, '<em style="color:#cbd5e1;">$1</em>')
    // Horizontal rules
    .replace(/^---+$/gm, '<hr style="border:none;border-top:1px solid rgba(255,255,255,.08);margin:12px 0;">')
    // Markdown links
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener" style="color:#22d3ee;text-decoration:underline;word-break:break-all;">$1</a>')
    // Bare URLs  
    .replace(/(?<![="'])(https?:\/\/[^\s<>"',)]+)/g, '<a href="$1" target="_blank" rel="noopener" style="color:#22d3ee;text-decoration:underline;word-break:break-all;">$1</a>')
    // Bullet lists — convert to styled list items
    .replace(/^[ \t]*[-*•] (.+)$/gm, '<li class="_md-li" style="margin:3px 0;padding-left:4px;">$1</li>')
    // Numbered lists
    .replace(/^[ \t]*(\d+)\. (.+)$/gm, '<li class="_md-li _md-ol" style="margin:3px 0;padding-left:4px;">$2</li>')
    // Tables — convert | col | col | rows
    .replace(/^\|(.+)\|$/gm, (m) => {
      // Skip separator rows like |---|---|
      if (/^\|[-:\s|]+\|$/.test(m)) return '<tr class="_md-tr-sep"></tr>';
      const cells = m.slice(1, -1).split('|').map(c => c.trim());
      return '<tr class="_md-tr">' + cells.map(c => `<td style="padding:5px 10px;border:1px solid rgba(255,255,255,.1);color:#cbd5e1;">${c}</td>`).join('') + '</tr>';
    });

  // Step 3: HTML-escape any remaining raw < > & in plain text sections
  // We need to escape characters NOT inside our already-inserted HTML tags
  // Simple approach: escape the text nodes only (between HTML tags)
  safe = safe.replace(/(?<=^|>)[^<]*/g, chunk => chunk.replace(/&(?![a-zA-Z#]\w*;)/g, '&amp;'));

  // Step 4: Convert line breaks to <br>, but NOT inside block elements
  safe = safe.replace(/\n\n+/g, '<br><br>').replace(/\n/g, '<br>');

  // Step 5: Restore code blocks
  safe = safe.replace(/\x00CODE(\d+)\x00/g, (_, idx) => codeBlocks[+idx] || '');

  // Step 6: Wrap list items in <ul>/<ol>
  safe = safe.replace(/(<li class="_md-li(?! _md-ol)[^"]*"[^>]*>[\s\S]*?<\/li>(\s*|<br>)*)+/g,
    m => `<ul style="margin:6px 0;padding-left:20px;list-style:disc;">${m.replace(/<br>/g,'')}</ul>`);
  safe = safe.replace(/(<li class="_md-li _md-ol"[^>]*>[\s\S]*?<\/li>(\s*|<br>)*)+/g,
    m => `<ol style="margin:6px 0;padding-left:20px;">${m.replace(/<br>/g,'')}</ol>`);

  // Step 7: Wrap table rows
  safe = safe.replace(/((?:<tr class="_md-tr[^"]*"[^>]*>[\s\S]*?<\/tr>)\s*)+/g,
    m => `<div style="overflow-x:auto;margin:8px 0;"><table style="border-collapse:collapse;width:100%;font-size:.85em;">${m.replace(/<tr class="_md-tr-sep"[^>]*>.*?<\/tr>/g, '')}</table></div>`);

  return `<div style="line-height:1.7;font-size:.9em;color:#cbd5e1;">${safe}</div>`;
}

/* ═══════════════════════════════════════════════════════
   ACTION LOGS
═══════════════════════════════════════════════════════ */
function _orchLog(action, detail, level='info') {
  AIORCH.logs.unshift({
    id: 'log-' + Date.now(),
    action,
    detail,
    level,
    ts: new Date().toISOString(),
    session: AIORCH.sessionId,
  });
  if (AIORCH.logs.length > 200) AIORCH.logs.pop();
  _orchUpdateLogBadge();
}

function _orchUpdateLogBadge() {
  const el = document.getElementById('orch-log-count');
  if (el) el.textContent = AIORCH.logs.length;
}

/* ═══════════════════════════════════════════════════════
   MAIN RENDERER
═══════════════════════════════════════════════════════ */
window.renderAIOrchestrator = function() {
  const c = document.getElementById('page-ai-orchestrator') || document.getElementById('aiOrchestratorContainer');
  if (!c) return;
  c.className = 'p19-module';

  const provider = AIORCH.aiProvider;
  const providerBadge = provider === 'openai' ? '<span class="p19-badge p19-badge--blue"><i class="fab fa-openai" style="margin-right:3px"></i>GPT-4</span>' :
                        provider === 'claude' ? '<span class="p19-badge p19-badge--purple">Claude</span>' :
                        '<span class="p19-badge p19-badge--cyan">Platform AI</span>';

  c.innerHTML = `
  <!-- Header -->
  <div class="p19-header">
    <div class="p19-header__inner">
      <div class="p19-header__left">
        <div class="p19-header__icon p19-header__icon--purple">
          <i class="fas fa-robot"></i>
          <span style="position:absolute;top:-3px;right:-3px;width:9px;height:9px;background:var(--p19-green);border-radius:50%;border:2px solid var(--p19-bg-1);animation:p19-blink 2s infinite"></span>
        </div>
        <div>
          <h2 class="p19-header__title">AI Orchestrator</h2>
          <div class="p19-header__sub">Agentic threat investigation · IOC enrichment · Multi-source intel</div>
        </div>
        ${providerBadge}
      </div>
      <div class="p19-header__right">
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="_orchConfigAI()">
          <i class="fas fa-key"></i> <span>API Keys</span>
        </button>
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="_orchShowLogs()">
          <i class="fas fa-list"></i> <span>Logs <span id="orch-log-count" style="background:rgba(239,68,68,.2);padding:1px 5px;border-radius:3px;font-size:.8em">${AIORCH.logs.length}</span></span>
        </button>
        <button class="p19-btn p19-btn--purple p19-btn--sm" onclick="_orchExportReport()">
          <i class="fas fa-download"></i> <span>Export</span>
        </button>
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="_orchNewSession()">
          <i class="fas fa-plus"></i> <span>New</span>
        </button>
      </div>
    </div>
  </div>

  <!-- Main Layout -->
  <div class="p19-ai-layout" style="border-top:1px solid var(--p19-border)">

    <!-- Sessions Panel (left) -->
    <div class="p19-ai-sessions-panel">
      <div style="padding:12px 14px;border-bottom:1px solid var(--p19-border)">
        <div style="font-size:.72em;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--p19-t3)">Sessions</div>
      </div>
      <div id="orch-sessions-list" style="overflow-y:auto;flex:1">
        <div style="padding:8px;display:flex;flex-direction:column;gap:4px">
          <div style="padding:9px 10px;border-radius:8px;background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.2);cursor:pointer">
            <div style="font-size:.8em;font-weight:600;color:var(--p19-t1)" id="orch-session-title">${_e(AIORCH.sessionTitle)}</div>
            <div style="font-size:.7em;color:var(--p19-t4);margin-top:2px">${AIORCH.msgCount} messages · Active</div>
          </div>
        </div>
      </div>

      <!-- Quick Tools -->
      <div style="padding:10px 14px;border-top:1px solid var(--p19-border)">
        <div style="font-size:.68em;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--p19-t4);margin-bottom:8px">Quick Actions</div>
        <div style="display:flex;flex-direction:column;gap:4px">
          <button class="p19-btn p19-btn--ghost p19-btn--sm" style="justify-content:flex-start;font-size:.76em" onclick="_orchQuick('Investigate IOC')">
            <i class="fas fa-fingerprint" style="color:var(--p19-cyan);width:14px"></i> IOC Lookup
          </button>
          <button class="p19-btn p19-btn--ghost p19-btn--sm" style="justify-content:flex-start;font-size:.76em" onclick="_orchQuick('Show top active threats today')">
            <i class="fas fa-fire" style="color:var(--p19-red);width:14px"></i> Top Threats
          </button>
          <button class="p19-btn p19-btn--ghost p19-btn--sm" style="justify-content:flex-start;font-size:.76em" onclick="_orchQuick('Show active ransomware campaigns')">
            <i class="fas fa-lock" style="color:var(--p19-orange);width:14px"></i> Ransomware Intel
          </button>
          <button class="p19-btn p19-btn--ghost p19-btn--sm" style="justify-content:flex-start;font-size:.76em" onclick="_orchQuick('Give me an executive threat summary')">
            <i class="fas fa-chart-pie" style="color:var(--p19-purple);width:14px"></i> Threat Summary
          </button>
        </div>
      </div>
    </div>

    <!-- Chat Panel (center) -->
    <div class="p19-ai-chat-panel">
      <!-- Chat sub-header -->
      <div style="padding:10px 16px;border-bottom:1px solid var(--p19-border);display:flex;align-items:center;gap:10px">
        <i class="fas fa-brain" style="color:var(--p19-purple);font-size:.9em"></i>
        <span style="font-size:.84em;font-weight:600;color:var(--p19-t1);flex:1">Investigation Session</span>
        <span id="orch-think-badge" style="display:none" class="p19-badge p19-badge--purple">
          <i class="fas fa-circle-notch fa-spin" style="margin-right:4px"></i>Analyzing…
        </span>
      </div>

      <!-- Messages -->
      <div class="p19-chat-messages" id="orch-messages">
        <!-- Welcome -->
        <div class="p19-msg p19-msg--assistant">
          <div class="p19-msg__avatar" style="background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.2);color:var(--p19-purple)">
            <i class="fas fa-robot"></i>
          </div>
          <div class="p19-msg__bubble">
            <p style="margin:0 0 8px"><strong>👋 Wadjet-Eye AI Orchestrator</strong> — Agentic Cyber Threat Intelligence</p>
            <p style="margin:0 0 8px;font-size:.9em;color:var(--p19-t2)">I can investigate IOCs across VirusTotal, AbuseIPDB, Shodan, and AlienVault OTX in parallel, map MITRE ATT&CK techniques, and generate exportable intelligence reports.</p>
            <div style="background:rgba(168,85,247,.06);border:1px solid rgba(168,85,247,.15);border-radius:8px;padding:10px;font-size:.82em">
              <div style="color:var(--p19-t3);margin-bottom:6px;font-weight:600;font-size:.86em">ACTIVE INTEGRATION</div>
              <div style="display:flex;gap:10px;flex-wrap:wrap">
                <span class="p19-badge p19-badge--cyan" style="font-size:.7em"><i class="fas fa-check" style="margin-right:3px"></i>Platform AI (Ollama/Backend)</span>
                ${AIORCH.apiKeys.openai ? '<span class="p19-badge p19-badge--blue" style="font-size:.7em"><i class="fas fa-check" style="margin-right:3px"></i>OpenAI GPT-4</span>' : ''}
                ${AIORCH.apiKeys.claude ? '<span class="p19-badge p19-badge--purple" style="font-size:.7em"><i class="fas fa-check" style="margin-right:3px"></i>Claude</span>' : ''}
                ${AIORCH.apiKeys.virustotal ? '<span class="p19-badge p19-badge--blue" style="font-size:.7em"><i class="fas fa-check" style="margin-right:3px"></i>VirusTotal</span>' : '<span class="p19-badge p19-badge--gray" style="font-size:.7em;opacity:.6">VT</span>'}
                ${AIORCH.apiKeys.abuseipdb ? '<span class="p19-badge p19-badge--red" style="font-size:.7em"><i class="fas fa-check" style="margin-right:3px"></i>AbuseIPDB</span>' : '<span class="p19-badge p19-badge--gray" style="font-size:.7em;opacity:.6">AbuseIPDB</span>'}
                ${AIORCH.apiKeys.shodan ? '<span class="p19-badge p19-badge--orange" style="font-size:.7em"><i class="fas fa-check" style="margin-right:3px"></i>Shodan</span>' : '<span class="p19-badge p19-badge--gray" style="font-size:.7em;opacity:.6">Shodan</span>'}
              </div>
              <div style="margin-top:8px;font-size:.78em;color:var(--p19-t3)">
                <i class="fas fa-circle" style="color:var(--p19-green);margin-right:4px;font-size:.6em"></i>
                Platform AI is active. Optionally add API keys in <button onclick="_orchConfigAI()" style="background:none;border:none;color:var(--p19-cyan);cursor:pointer;padding:0;font-size:1em;text-decoration:underline">API Keys</button> for multi-source enrichment.
              </div>
            </div>
          </div>
        </div>

        <!-- Suggestions -->
        <div id="orch-suggestions" style="padding:4px 0">
          <div style="font-size:.72em;color:var(--p19-t4);margin-bottom:8px;padding-left:44px;text-transform:uppercase;letter-spacing:.06em">Quick Prompts</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;padding-left:44px">
            ${[
              {icon:'🔍',text:'Investigate IP 185.220.101.45'},
              {icon:'🦠',text:'Analyze hash a3f2b1c9d4e5f67890ab1234567890cd'},
              {icon:'🌐',text:'Check domain malicious-update.ru'},
              {icon:'🔒',text:'Show top ransomware threats in healthcare'},
              {icon:'🎯',text:'Who is APT29 and their latest TTPs?'},
              {icon:'⚡',text:'Active campaigns targeting financial sector'},
              {icon:'📊',text:'Give me an executive threat intelligence summary'},
              {icon:'🛡️',text:'What are the top CVEs being exploited right now?'},
            ].map(s=>`
              <button onclick="_orchQuick(${JSON.stringify(s.text)})"
                class="p19-btn p19-btn--ghost p19-btn--sm" style="font-size:.76em">
                ${s.icon} ${_e(s.text.slice(0,36))}${s.text.length>36?'…':''}
              </button>`).join('')}
          </div>
        </div>
      </div>

      <!-- Input -->
      <div class="p19-chat-input-area">
        <div style="display:flex;align-items:center;gap:6px;flex-shrink:0">
          <select id="orch-provider" style="background:var(--p19-bg-input);border:1px solid var(--p19-border);border-radius:6px;padding:6px 8px;color:var(--p19-t2);font-size:.76em;cursor:pointer" onchange="AIORCH.aiProvider=this.value;localStorage.setItem('wadjet_ai_provider',this.value);_toast('AI provider: '+this.value,'info')">
            <option value="platform"${AIORCH.aiProvider==='platform'?' selected':''}>Platform AI</option>
            <option value="openai"${AIORCH.aiProvider==='openai'?' selected':''}>OpenAI GPT-4</option>
            <option value="claude"${AIORCH.aiProvider==='claude'?' selected':''}>Claude</option>
          </select>
        </div>
        <textarea id="orch-input" rows="1"
          placeholder="Investigate an IOC, ask about threats, or type a question… (Enter to send)"
          onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();window._orchSend()}"
          oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,120)+'px'"></textarea>
        <button class="p19-btn p19-btn--purple p19-btn--sm" onclick="window._orchSend()" id="orch-send-btn" style="height:38px;flex-shrink:0;padding:0 14px">
          <i class="fas fa-paper-plane"></i>
        </button>
      </div>
    </div>

    <!-- Tools Panel (right) -->
    <div class="p19-ai-tools-panel">
      <div style="padding:12px 14px;border-bottom:1px solid var(--p19-border)">
        <div style="font-size:.72em;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--p19-t3)">Intel Tools</div>
      </div>
      <div style="padding:8px 0">
        ${[
          {icon:'fa-virus',        color:'var(--p19-blue)',   label:'VirusTotal',       desc:'File/URL/IP/Domain scan', key:'virustotal'},
          {icon:'fa-shield-alt',   color:'var(--p19-red)',    label:'AbuseIPDB',         desc:'IP reputation',          key:'abuseipdb'},
          {icon:'fa-server',       color:'var(--p19-orange)', label:'Shodan',            desc:'Port/service enum',       key:'shodan'},
          {icon:'fa-satellite',    color:'var(--p19-purple)', label:'AlienVault OTX',    desc:'Threat pulses',           key:'otx'},
          {icon:'fa-crosshairs',   color:'var(--p19-green)',  label:'Campaign Hunt',     desc:'IOC clustering',          key:null},
          {icon:'fa-th',           color:'var(--p19-yellow)', label:'MITRE ATT&CK',      desc:'TTP mapping',             key:null},
          {icon:'fa-folder-plus',  color:'var(--p19-cyan)',   label:'Create Case',       desc:'DFIR case creation',      key:null},
          {icon:'fa-download',     color:'var(--p19-indigo)', label:'Export Report',     desc:'PDF / JSON / CSV',        key:null},
        ].map(t=>`
        <div class="p19-tool-card" onclick="_orchUseTool('${t.label}')">
          <div class="p19-tool-card__icon" style="background:${t.color}1a;border:1px solid ${t.color}33;color:${t.color}">
            <i class="fas ${t.icon}"></i>
          </div>
          <div style="min-width:0">
            <div class="p19-tool-card__name">${t.label}</div>
            <div class="p19-tool-card__desc">${t.desc}</div>
          </div>
          ${t.key && AIORCH.apiKeys[t.key] ? '<i class="fas fa-check-circle" style="color:var(--p19-green);font-size:.7em;margin-left:auto;flex-shrink:0"></i>' :
            t.key ? '<i class="fas fa-exclamation-circle" style="color:var(--p19-t4);font-size:.7em;margin-left:auto;flex-shrink:0"></i>' : ''}
        </div>`).join('')}
      </div>
    </div>
  </div>
  `;
};

/* ═══════════════════════════════════════════════════════
   GLOBAL ACTIONS
═══════════════════════════════════════════════════════ */
window._orchSend = function() {
  const inp = document.getElementById('orch-input');
  if (!inp) return;
  const val = inp.value.trim();
  if (!val || AIORCH.isThinking) return;
  inp.value = '';
  inp.style.height = 'auto';
  const sendBtn = document.getElementById('orch-send-btn');
  if (sendBtn) sendBtn.disabled = true;
  _orchSendMessage(val);
};

window._orchQuick = function(text) {
  const inp = document.getElementById('orch-input');
  if (inp) { inp.value = text; inp.focus(); }
  window._orchSend();
};

window._orchUseTool = function(tool) {
  const prompts = {
    'VirusTotal':      'Perform a VirusTotal scan on ',
    'AbuseIPDB':       'Check AbuseIPDB reputation for IP: ',
    'Shodan':          'Look up Shodan data for IP: ',
    'AlienVault OTX':  'Check OTX threat pulses for IOC: ',
    'Campaign Hunt':   'Show me active campaigns correlating to recent IOCs',
    'MITRE ATT&CK':    'Map the latest threat actor TTPs to MITRE ATT&CK framework',
    'Create Case':     'Create a DFIR case from this investigation session',
    'Export Report':   window._orchExportReport,
  };
  const action = prompts[tool];
  if (typeof action === 'function') { action(); return; }
  if (action) {
    const inp = document.getElementById('orch-input');
    if (inp) { inp.value = action; inp.focus(); }
  }
  _toast(`Tool loaded: ${tool}`, 'info');
};

window._orchNewSession = function() {
  AIORCH.messages = [];
  AIORCH.sessionId = _genId();
  AIORCH.sessionTitle = 'New Investigation';
  AIORCH.msgCount = 0;
  window.renderAIOrchestrator();
  _toast('New session started', 'success');
};

window._orchShowLogs = function() {
  const modal = document.createElement('div');
  modal.className = 'p19-modal-backdrop';
  modal.onclick = (e) => { if (e.target===modal) modal.remove(); };
  modal.innerHTML = `
  <div class="p19-modal p19-modal--lg">
    <div class="p19-modal-head">
      <div class="p19-modal-title"><i class="fas fa-list" style="margin-right:8px;color:var(--p19-cyan)"></i>Action Logs (${AIORCH.logs.length})</div>
      <button class="p19-modal-close" onclick="this.closest('.p19-modal-backdrop').remove()"><i class="fas fa-times"></i></button>
    </div>
    <div class="p19-modal-body" style="max-height:400px;overflow-y:auto">
      ${AIORCH.logs.length ? AIORCH.logs.map(l=>`
      <div class="p19-audit-item">
        <div class="p19-audit-icon" style="background:${l.level==='error'?'rgba(239,68,68,.1)':l.level==='warning'?'rgba(234,179,8,.1)':'rgba(34,211,238,.08)'};color:${l.level==='error'?'var(--p19-red)':l.level==='warning'?'var(--p19-yellow)':'var(--p19-cyan)'}">
          <i class="fas ${l.level==='error'?'fa-exclamation-circle':l.level==='warning'?'fa-exclamation-triangle':'fa-info-circle'}"></i>
        </div>
        <div class="p19-audit-msg">
          <strong style="color:var(--p19-t1)">${_e(l.action)}</strong>
          <div style="font-size:.9em;color:var(--p19-t3)">${_e(l.detail)}</div>
        </div>
        <div class="p19-audit-time">${_e(l.ts?.slice(11,19))}</div>
      </div>`).join('') : `<div class="p19-empty"><i class="fas fa-list"></i><div class="p19-empty-title">No logs yet</div></div>`}
    </div>
    <div class="p19-modal-foot">
      <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="AIORCH.logs=[];_toast('Logs cleared','info');this.closest('.p19-modal-backdrop').remove()">
        <i class="fas fa-trash"></i> Clear Logs
      </button>
      <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="this.closest('.p19-modal-backdrop').remove()">Close</button>
    </div>
  </div>`;
  document.body.appendChild(modal);
};

window._orchExportReport = function() {
  const report = {
    title: 'Wadjet-Eye AI Investigation Report',
    session: AIORCH.sessionId,
    session_title: AIORCH.sessionTitle,
    ai_provider: AIORCH.aiProvider,
    generated_at: new Date().toISOString(),
    message_count: AIORCH.msgCount,
    conversation: AIORCH.messages.map(m=>({
      role: m.role,
      content: m.content,
      timestamp: new Date(m.ts).toISOString(),
    })),
    action_logs: AIORCH.logs,
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `ai-investigation-${AIORCH.sessionId}-${Date.now()}.json`;
  a.click();
  _toast('Investigation report exported as JSON', 'success');
  _orchLog('export', `Report exported: ${AIORCH.sessionId}`);
};

window._orchConfigAI = function() {
  const modal = document.createElement('div');
  modal.className = 'p19-modal-backdrop';
  modal.onclick = (e) => { if (e.target===modal) modal.remove(); };
  modal.innerHTML = `
  <div class="p19-modal">
    <div class="p19-modal-head">
      <div class="p19-modal-title"><i class="fas fa-key" style="margin-right:8px;color:var(--p19-cyan)"></i>AI & API Key Configuration</div>
      <button class="p19-modal-close" onclick="this.closest('.p19-modal-backdrop').remove()"><i class="fas fa-times"></i></button>
    </div>
    <div class="p19-modal-body">
      <div class="p19-alert p19-alert--info" style="margin-bottom:16px">
        <i class="fas fa-info-circle"></i>
        <span>API keys are stored in your browser's localStorage. They are never sent to our servers — only used for direct API calls from your browser.</span>
      </div>
      <div class="p19-form-group">
        <label class="p19-form-label">AI Provider</label>
        <select id="cfg-provider" class="p19-form-select">
          <option value="platform"${AIORCH.aiProvider==='platform'?' selected':''}>Platform AI (default)</option>
          <option value="openai"${AIORCH.aiProvider==='openai'?' selected':''}>OpenAI GPT-4o</option>
          <option value="claude"${AIORCH.aiProvider==='claude'?' selected':''}>Anthropic Claude 3.5</option>
        </select>
      </div>
      <div class="p19-divider">AI Keys</div>
      <div class="p19-form-group">
        <label class="p19-form-label">OpenAI API Key</label>
        <input type="password" class="p19-form-input" id="cfg-openai" value="${AIORCH.apiKeys.openai}" placeholder="sk-...">
        <div class="p19-form-hint">Required for GPT-4 · <a href="https://platform.openai.com/api-keys" target="_blank" style="color:var(--p19-cyan)">Get key</a></div>
      </div>
      <div class="p19-form-group">
        <label class="p19-form-label">Anthropic Claude API Key</label>
        <input type="password" class="p19-form-input" id="cfg-claude" value="${AIORCH.apiKeys.claude}" placeholder="sk-ant-...">
        <div class="p19-form-hint">Required for Claude · <a href="https://console.anthropic.com" target="_blank" style="color:var(--p19-cyan)">Get key</a></div>
      </div>
      <div class="p19-divider">Intel Sources</div>
      <div class="p19-form-row">
        <div class="p19-form-group">
          <label class="p19-form-label">VirusTotal API Key</label>
          <input type="password" class="p19-form-input" id="cfg-vt" value="${AIORCH.apiKeys.virustotal}" placeholder="VT API key">
          <div class="p19-form-hint"><a href="https://www.virustotal.com/gui/my-apikey" target="_blank" style="color:var(--p19-cyan)">Get key (free)</a></div>
        </div>
        <div class="p19-form-group">
          <label class="p19-form-label">AbuseIPDB API Key</label>
          <input type="password" class="p19-form-input" id="cfg-abuseipdb" value="${AIORCH.apiKeys.abuseipdb}" placeholder="AbuseIPDB key">
          <div class="p19-form-hint"><a href="https://www.abuseipdb.com/account/api" target="_blank" style="color:var(--p19-cyan)">Get key (free)</a></div>
        </div>
        <div class="p19-form-group">
          <label class="p19-form-label">Shodan API Key</label>
          <input type="password" class="p19-form-input" id="cfg-shodan" value="${AIORCH.apiKeys.shodan}" placeholder="Shodan key">
          <div class="p19-form-hint"><a href="https://account.shodan.io" target="_blank" style="color:var(--p19-cyan)">Get key</a></div>
        </div>
        <div class="p19-form-group">
          <label class="p19-form-label">AlienVault OTX Key</label>
          <input type="password" class="p19-form-input" id="cfg-otx" value="${AIORCH.apiKeys.otx}" placeholder="OTX API key">
          <div class="p19-form-hint"><a href="https://otx.alienvault.com/api" target="_blank" style="color:var(--p19-cyan)">Get key (free)</a></div>
        </div>
      </div>
    </div>
    <div class="p19-modal-foot">
      <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="this.closest('.p19-modal-backdrop').remove()">Cancel</button>
      <button class="p19-btn p19-btn--primary p19-btn--sm" onclick="window._orchSaveConfig(this)">
        <i class="fas fa-save"></i> Save & Apply
      </button>
    </div>
  </div>`;
  document.body.appendChild(modal);
};

window._orchSaveConfig = function(btn) {
  const get = id => document.getElementById(id)?.value?.trim() || '';
  AIORCH.apiKeys.openai     = get('cfg-openai');
  AIORCH.apiKeys.claude     = get('cfg-claude');
  AIORCH.apiKeys.virustotal = get('cfg-vt');
  AIORCH.apiKeys.abuseipdb  = get('cfg-abuseipdb');
  AIORCH.apiKeys.shodan     = get('cfg-shodan');
  AIORCH.apiKeys.otx        = get('cfg-otx');
  AIORCH.aiProvider         = get('cfg-provider') || 'platform';

  // Save to localStorage
  Object.entries({
    wadjet_openai_key:    AIORCH.apiKeys.openai,
    wadjet_claude_key:    AIORCH.apiKeys.claude,
    wadjet_vt_key:        AIORCH.apiKeys.virustotal,
    wadjet_abuseipdb_key: AIORCH.apiKeys.abuseipdb,
    wadjet_shodan_key:    AIORCH.apiKeys.shodan,
    wadjet_otx_key:       AIORCH.apiKeys.otx,
    wadjet_ai_provider:   AIORCH.aiProvider,
  }).forEach(([k,v]) => { if (v) localStorage.setItem(k,v); else localStorage.removeItem(k); });

  btn.closest('.p19-modal-backdrop').remove();
  _toast('API keys saved. Reloading orchestrator…', 'success');
  _orchLog('config_saved', `Provider: ${AIORCH.aiProvider}, VT: ${!!AIORCH.apiKeys.virustotal}, OTX: ${!!AIORCH.apiKeys.otx}`);

  setTimeout(() => window.renderAIOrchestrator(), 500);
};

})(); // end IIFE
