/**
 * ══════════════════════════════════════════════════════════
 *  ThreatPilot AI — AI Orchestrator Frontend v3.0
 *  js/ai-orchestrator.js
 *
 *  Provides:
 *   - Floating AI chat panel (injected into DOM)
 *   - Connects to /api/cti/ai/query endpoint
 *   - Suggested prompts
 *   - Markdown-like response rendering
 *   - Session history
 *   - Quick IOC lookup from anywhere in the app
 * ══════════════════════════════════════════════════════════
 */
'use strict';

(function () {
  // ── State ──────────────────────────────────────────────
  let isOpen          = false;
  let isThinking      = false;
  let messageHistory  = [];
  let sessionTitle    = null;

  // ── Suggested prompts ─────────────────────────────────
  const SUGGESTIONS = [
    { icon: '🔍', text: 'Show top active threats' },
    { icon: '📊', text: 'Give me a threat summary' },
    { icon: '🎯', text: 'Check feed status' },
    { icon: '🦠', text: 'Show high-risk IOCs' },
    { icon: '🕵️', text: 'Who is APT29?' },
    { icon: '⚡', text: 'Show active campaigns' },
  ];

  // ── Render markdown-like text ────────────────────────
  function renderText(text) {
    if (!text) return '';
    return text
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code style="background:#1a1a2e;padding:1px 5px;border-radius:3px;font-size:0.85em">$1</code>')
      .replace(/\n\n/g, '</p><p>')
      .replace(/\n/g, '<br>')
      .replace(/^(•\s.+)/gm, '<li>$1</li>')
      .replace(/<li>•\s/g, '<li>');
  }

  // ── Risk badge ────────────────────────────────────────
  function riskBadge(score) {
    if (!score && score !== 0) return '';
    const cls = score >= 70 ? 'critical' : score >= 40 ? 'high' : score >= 20 ? 'medium' : 'low';
    const colors = { critical: '#ff4444', high: '#ff8800', medium: '#ffcc00', low: '#00cc44' };
    return `<span style="background:${colors[cls]};color:#000;padding:2px 8px;border-radius:10px;font-size:0.75em;font-weight:700">Risk ${score}</span>`;
  }

  // ── Build message HTML ────────────────────────────────
  function buildAssistantMessage(result) {
    const sections = [];

    // Main explanation
    if (result.explanation) {
      sections.push(`<p>${renderText(result.explanation)}</p>`);
    }

    // IOC Lookup details
    if (result.tool === 'ioc_lookup' && result.ioc_value) {
      sections.push(`
        <div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;margin:8px 0">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
            <strong style="color:#58a6ff">${result.ioc_value}</strong>
            ${riskBadge(result.risk_score)}
          </div>
          <div style="font-size:0.8em;color:#8b949e">
            Type: ${result.ioc_type} | 
            Reputation: <span style="color:${result.reputation === 'malicious' ? '#ff4444' : result.reputation === 'suspicious' ? '#ff8800' : '#00cc44'}">${result.reputation || 'unknown'}</span> |
            In DB: ${result.found_in_db ? '✓' : '✗'}
          </div>
          ${result.mitre_techniques?.length > 0 ? `<div style="margin-top:4px;font-size:0.78em;color:#8b949e">MITRE: ${result.mitre_techniques.slice(0,4).join(' · ')}</div>` : ''}
        </div>
      `);
    }

    // Alert summary
    if (result.tool === 'alert_summary' && result.stats_24h) {
      const s = result.stats_24h;
      sections.push(`
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:8px 0">
          <div style="background:#1a1a2e;border:1px solid #ff444422;border-radius:6px;padding:8px;text-align:center">
            <div style="font-size:1.4em;font-weight:700;color:#ff4444">${s.critical}</div>
            <div style="font-size:0.7em;color:#8b949e">Critical</div>
          </div>
          <div style="background:#1a1a2e;border:1px solid #ff880022;border-radius:6px;padding:8px;text-align:center">
            <div style="font-size:1.4em;font-weight:700;color:#ff8800">${s.high}</div>
            <div style="font-size:0.7em;color:#8b949e">High</div>
          </div>
          <div style="background:#1a1a2e;border:1px solid #ffcc0022;border-radius:6px;padding:8px;text-align:center">
            <div style="font-size:1.4em;font-weight:700;color:#ffcc00">${s.open}</div>
            <div style="font-size:0.7em;color:#8b949e">Open</div>
          </div>
        </div>
      `);
    }

    // Feed status
    if (result.tool === 'feed_status' && result.feeds?.length > 0) {
      sections.push(`
        <div style="margin:8px 0">
          ${result.feeds.map(f => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid #21262d;font-size:0.82em">
              <span>${f.feed_name}</span>
              <span style="color:${f.status === 'success' ? '#3fb950' : f.status === 'error' ? '#ff4444' : '#8b949e'}">${f.status}</span>
              <span style="color:#8b949e">+${f.iocs_new || 0} IOCs</span>
            </div>
          `).join('')}
        </div>
      `);
    }

    // Actor info
    if (result.tool === 'threat_actor_info' && result.actor) {
      const a = result.actor;
      sections.push(`
        <div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;margin:8px 0">
          <strong style="color:#58a6ff">${a.name}</strong>
          <div style="font-size:0.8em;color:#8b949e;margin-top:4px">
            Origin: ${a.origin_country || '?'} | Sophistication: ${a.sophistication || '?'} | Motivation: ${a.motivation || '?'}
          </div>
          ${a.ttps?.length > 0 ? `<div style="margin-top:4px;font-size:0.78em;color:#8b949e">TTPs: ${a.ttps.slice(0,5).join(', ')}</div>` : ''}
        </div>
      `);
    }

    // List of IOCs
    if (result.tool === 'ioc_search' && result.iocs?.length > 0) {
      sections.push(`
        <div style="margin:8px 0;max-height:200px;overflow-y:auto">
          ${result.iocs.slice(0, 10).map(i => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid #21262d;font-size:0.8em">
              <span style="color:#58a6ff;max-width:60%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${i.value}">${i.value}</span>
              <span style="color:#8b949e">${i.type}</span>
              ${riskBadge(i.risk_score)}
            </div>
          `).join('')}
        </div>
      `);
    }

    // Processing time
    if (result.processing_ms) {
      sections.push(`<div style="font-size:0.7em;color:#484f58;margin-top:6px">⚡ ${result.processing_ms}ms · ${result.intent || 'general'}</div>`);
    }

    return sections.join('');
  }

  // ── Append message to chat ────────────────────────────
  function appendMessage(role, content, rawResult = null) {
    const chat = document.getElementById('ai-chat-messages');
    if (!chat) return;

    const div  = document.createElement('div');
    const isUser = role === 'user';

    div.style.cssText = `
      display:flex; flex-direction:column; align-items:${isUser ? 'flex-end' : 'flex-start'};
      margin-bottom:12px; animation:fadeIn 0.2s ease;
    `;

    const bubble = document.createElement('div');
    bubble.style.cssText = `
      max-width:90%; padding:10px 14px; border-radius:${isUser ? '12px 12px 2px 12px' : '12px 12px 12px 2px'};
      background:${isUser ? '#1f6feb' : '#161b22'}; border:1px solid ${isUser ? 'transparent' : '#30363d'};
      font-size:0.875em; line-height:1.5; color:#e6edf3; word-break:break-word;
    `;

    if (isUser) {
      bubble.textContent = content;
    } else if (rawResult) {
      bubble.innerHTML = buildAssistantMessage(rawResult);
    } else {
      bubble.innerHTML = `<p>${renderText(content)}</p>`;
    }

    div.appendChild(bubble);
    chat.appendChild(div);
    chat.scrollTop = chat.scrollHeight;

    // Track history
    messageHistory.push({ role, content: isUser ? content : (rawResult?.explanation || content) });
  }

  // ── Thinking indicator ────────────────────────────────
  function showThinking() {
    const chat = document.getElementById('ai-chat-messages');
    if (!chat) return;
    const div = document.createElement('div');
    div.id = 'ai-thinking';
    div.style.cssText = 'display:flex;align-items:flex-start;margin-bottom:12px';
    div.innerHTML = `
      <div style="background:#161b22;border:1px solid #30363d;border-radius:12px 12px 12px 2px;padding:10px 14px;font-size:0.875em;color:#8b949e">
        <span class="thinking-dots">Analysing</span>
        <span style="animation:blink 1s infinite;font-size:1.2em">▋</span>
      </div>
    `;
    chat.appendChild(div);
    chat.scrollTop = chat.scrollHeight;
  }

  function hideThinking() {
    const el = document.getElementById('ai-thinking');
    if (el) el.remove();
  }

  // ── Send query ────────────────────────────────────────
  async function sendQuery(queryText) {
    if (!queryText.trim() || isThinking) return;

    // Warn but don't abort — the fetch inside ctiRequest may still succeed
    if (!window.CTI) {
      console.warn('[AI Orchestrator] CTI object not loaded yet — will retry after 800ms');
      setTimeout(() => sendQuery(queryText), 800);
      return;
    }

    isThinking = true;
    appendMessage('user', queryText);

    const input = document.getElementById('ai-chat-input');
    const btn   = document.getElementById('ai-send-btn');
    if (input) input.value = '';
    if (btn)   btn.disabled = true;

    showThinking();

    try {
      const result = await CTI.ai.query(queryText);
      hideThinking();

      if (result && (result.explanation || result.tool)) {
        appendMessage('assistant', result.explanation || 'Query processed.', result);
      } else if (!result) {
        // Back-end returned null — session expired or backend unreachable
        const backendUrl = window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com';
        appendMessage('assistant',
          `⚠️ **AI agent did not respond.**\n\n` +
          `**Possible causes:**\n` +
          `• Session expired — please log out and log back in\n` +
          `• Backend unreachable: \`${backendUrl}\`\n` +
          `• Backend is starting up (Render free tier spins down after 15 min — wait 30s and retry)\n` +
          `• Missing API keys: OPENAI_API_KEY, GEMINI_API_KEY\n\n` +
          `Ensure \`window.THREATPILOT_API_URL\` points to your running backend and all env vars are set in Render.`);
      } else {
        appendMessage('assistant', result.explanation || JSON.stringify(result), result);
      }
    } catch (err) {
      hideThinking();
      const msg = err.message || 'Unknown error';
      if (msg.includes('401') || msg.includes('403') || msg.includes('Auth error')) {
        appendMessage('assistant',
          `🔐 **Authentication required.**\n\nYour session may have expired. Please refresh the page and log in again.\n\nBackend: \`${window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com'}\``);
      } else {
        appendMessage('assistant',
          `❌ **Request failed:** ${msg}\n\n` +
          (msg.includes('fetch') || msg.includes('Failed') || msg.includes('network')
            ? `Check that \`window.THREATPILOT_API_URL\` points to your running backend.`
            : 'Please try again.'));
      }
    } finally {
      isThinking = false;
      if (btn) btn.disabled = false;
      if (input) input.focus();
    }
  }

  // ── Build panel HTML ──────────────────────────────────
  function buildPanel() {
    const panel = document.createElement('div');
    panel.id = 'ai-orchestrator-panel';
    panel.style.cssText = `
      position:fixed; bottom:80px; right:20px; width:400px; max-width:calc(100vw - 40px);
      background:#0d1117; border:1px solid #30363d; border-radius:12px;
      box-shadow:0 16px 48px rgba(0,0,0,0.6); z-index:9999;
      display:none; flex-direction:column; max-height:600px;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    `;

    panel.innerHTML = `
      <style>
        @keyframes fadeIn { from { opacity:0; transform:translateY(5px); } to { opacity:1; transform:translateY(0); } }
        @keyframes blink  { 0%,100%{opacity:1} 50%{opacity:0} }
        #ai-chat-messages::-webkit-scrollbar { width:4px; }
        #ai-chat-messages::-webkit-scrollbar-track { background:#0d1117; }
        #ai-chat-messages::-webkit-scrollbar-thumb { background:#30363d; border-radius:2px; }
        #ai-chat-input { outline:none; }
        #ai-chat-input:focus { border-color:#1f6feb !important; }
        .ai-suggestion-btn:hover { background:#1f6feb22 !important; border-color:#1f6feb !important; }
      </style>

      <!-- Header -->
      <div style="display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid #21262d">
        <div style="display:flex;align-items:center;gap:8px">
          <div style="width:32px;height:32px;background:linear-gradient(135deg,#1f6feb,#a855f7);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px">🤖</div>
          <div>
            <div style="font-size:0.875em;font-weight:600;color:#e6edf3">ThreatPilot AI</div>
            <div style="font-size:0.7em;color:#3fb950">● Live</div>
          </div>
        </div>
        <div style="display:flex;gap:8px;align-items:center">
          <button id="ai-clear-btn" title="Clear chat" style="background:none;border:none;color:#8b949e;cursor:pointer;font-size:14px;padding:4px">🗑</button>
          <button id="ai-close-btn" style="background:none;border:none;color:#8b949e;cursor:pointer;font-size:18px;line-height:1;padding:4px">✕</button>
        </div>
      </div>

      <!-- Messages -->
      <div id="ai-chat-messages" style="flex:1;overflow-y:auto;padding:16px;min-height:200px;max-height:380px">
        <!-- Welcome message -->
        <div style="text-align:center;padding:20px 0;color:#8b949e;font-size:0.8em">
          <div style="font-size:2em;margin-bottom:8px">🔐</div>
          <div style="font-weight:600;color:#e6edf3;margin-bottom:4px">ThreatPilot AI Agent</div>
          <div>Ask me anything about your threat landscape</div>
        </div>
      </div>

      <!-- Suggestions -->
      <div id="ai-suggestions" style="padding:0 12px 8px;display:flex;flex-wrap:wrap;gap:6px">
        ${SUGGESTIONS.map(s => `
          <button class="ai-suggestion-btn" data-query="${s.text}" style="
            background:#161b22;border:1px solid #30363d;border-radius:16px;
            color:#8b949e;font-size:0.72em;padding:4px 10px;cursor:pointer;
            transition:all 0.15s;white-space:nowrap
          ">${s.icon} ${s.text}</button>
        `).join('')}
      </div>

      <!-- Input -->
      <div style="padding:12px;border-top:1px solid #21262d;display:flex;gap:8px;align-items:flex-end">
        <textarea id="ai-chat-input" rows="1" placeholder="Ask about threats, IOCs, actors..." style="
          flex:1;background:#161b22;border:1px solid #30363d;border-radius:8px;
          color:#e6edf3;font-size:0.875em;padding:8px 12px;resize:none;
          max-height:100px;line-height:1.4;
        "></textarea>
        <button id="ai-send-btn" style="
          background:#1f6feb;border:none;border-radius:8px;color:#fff;
          width:36px;height:36px;cursor:pointer;font-size:16px;flex-shrink:0;
          display:flex;align-items:center;justify-content:center;
          transition:background 0.15s;
        ">➤</button>
      </div>
    `;

    return panel;
  }

  // ── Build FAB button ──────────────────────────────────
  function buildFAB() {
    const btn = document.createElement('button');
    btn.id = 'ai-fab-btn';
    btn.title = 'ThreatPilot AI Agent';
    btn.style.cssText = `
      position:fixed; bottom:20px; right:20px;
      width:52px; height:52px; border-radius:50%;
      background:linear-gradient(135deg,#1f6feb,#a855f7);
      border:none; color:#fff; font-size:22px; cursor:pointer;
      box-shadow:0 4px 20px rgba(31,111,235,0.5);
      z-index:10000; display:flex; align-items:center; justify-content:center;
      transition:transform 0.2s,box-shadow 0.2s;
    `;
    btn.textContent = '🤖';
    btn.onmouseenter = () => { btn.style.transform = 'scale(1.1)'; };
    btn.onmouseleave = () => { btn.style.transform = 'scale(1)'; };
    return btn;
  }

  // ── Init ──────────────────────────────────────────────
  function init() {
    // Avoid double-init
    if (document.getElementById('ai-fab-btn')) return;

    const panel = buildPanel();
    const fab   = buildFAB();

    document.body.appendChild(panel);
    document.body.appendChild(fab);

    // FAB click → toggle panel
    fab.addEventListener('click', () => {
      isOpen = !isOpen;
      panel.style.display = isOpen ? 'flex' : 'none';
      fab.textContent = isOpen ? '✕' : '🤖';
      fab.style.background = isOpen
        ? 'linear-gradient(135deg,#ff4444,#cc0000)'
        : 'linear-gradient(135deg,#1f6feb,#a855f7)';

      if (isOpen) {
        setTimeout(() => {
          const input = document.getElementById('ai-chat-input');
          if (input) input.focus();
        }, 100);
      }
    });

    // Close button
    panel.querySelector('#ai-close-btn').addEventListener('click', () => {
      isOpen = false;
      panel.style.display = 'none';
      fab.textContent = '🤖';
      fab.style.background = 'linear-gradient(135deg,#1f6feb,#a855f7)';
    });

    // Clear button
    panel.querySelector('#ai-clear-btn').addEventListener('click', () => {
      const chat = document.getElementById('ai-chat-messages');
      if (chat) chat.innerHTML = '<div style="text-align:center;padding:20px;color:#8b949e;font-size:0.8em">Chat cleared</div>';
      messageHistory = [];
      document.getElementById('ai-suggestions').style.display = 'flex';
    });

    // Send button
    panel.querySelector('#ai-send-btn').addEventListener('click', () => {
      const input = document.getElementById('ai-chat-input');
      if (input) sendQuery(input.value.trim());
    });

    // Enter key in textarea (Shift+Enter = new line)
    const inputEl = panel.querySelector('#ai-chat-input');
    if (inputEl) {
      inputEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          sendQuery(inputEl.value.trim());
        }
      });

      // Auto-resize textarea
      inputEl.addEventListener('input', () => {
        inputEl.style.height = 'auto';
        inputEl.style.height = Math.min(100, inputEl.scrollHeight) + 'px';
      });
    }

    // Suggestion buttons
    panel.querySelectorAll('.ai-suggestion-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const q = btn.dataset.query;
        if (q) {
          document.getElementById('ai-suggestions').style.display = 'none';
          sendQuery(q);
        }
      });
    });

    console.log('[AI Orchestrator] ✓ Initialized');
  }

  // ── Public API ────────────────────────────────────────
  window.AIOrchestrator = {
    init,
    sendQuery,
    // Quick lookup from anywhere in the app
    lookupIOC: (value) => {
      if (!isOpen) {
        isOpen = true;
        const panel = document.getElementById('ai-orchestrator-panel');
        const fab   = document.getElementById('ai-fab-btn');
        if (panel) panel.style.display = 'flex';
        if (fab)   { fab.textContent = '✕'; fab.style.background = 'linear-gradient(135deg,#ff4444,#cc0000)'; }
      }
      sendQuery(`Check this ${value}`);
    },
  };

  // Auto-init when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    // Page already loaded (script injected after DOMContentLoaded)
    setTimeout(init, 100);
  }
})();
