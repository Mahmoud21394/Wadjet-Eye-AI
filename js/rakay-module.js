/**
 * ══════════════════════════════════════════════════════════════════════
 *  RAKAY Module — Frontend UI  v1.0
 *  Wadjet-Eye AI Platform — Conversational Security Analyst
 *
 *  Architecture:
 *   - Self-contained IIFE; exposes only window.renderRAKAY / window.stopRAKAY
 *   - API client: communicates with /api/RAKAY/* backend routes
 *   - Markdown renderer: inline, no external deps (marked.js loaded if present)
 *   - Tool-call visualiser: collapsible trace panel per message
 *   - Session sidebar: list, create, rename, delete sessions
 *   - Persistent session storage: localStorage (fallback when backend offline)
 *   - Professional dark UI matching Wadjet-Eye design system
 * ══════════════════════════════════════════════════════════════════════
 */
(function () {
  'use strict';

  // ── State ─────────────────────────────────────────────────────────────────
  const RAKAY = {
    sessionId:    null,
    sessions:     [],
    messages:     [],
    loading:      false,
    typing:       false,
    pollingTimer: null,
    apiBase:      (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,''),
    backendOnline: null,  // null = unknown
  };

  const PAGE_ID = 'rakay';
  let _rendered = false;

  // ── Helpers ───────────────────────────────────────────────────────────────
  function _e(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  function _uid() {
    return 'r_' + Date.now().toString(36) + Math.random().toString(36).slice(2,8);
  }

  function _time(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    const now = new Date();
    const diffMs  = now - d;
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1)  return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffH = Math.floor(diffMin / 60);
    if (diffH < 24) return `${diffH}h ago`;
    return d.toLocaleDateString();
  }

  // ── localStorage session fallback ─────────────────────────────────────────
  const LS_KEY_SESSIONS = 'rakay_sessions_v1';
  const LS_KEY_MSGS     = prefix => `rakay_msgs_${prefix}`;

  function _lsGetSessions() {
    try { return JSON.parse(localStorage.getItem(LS_KEY_SESSIONS) || '[]'); } catch { return []; }
  }
  function _lsSetSessions(arr) {
    try { localStorage.setItem(LS_KEY_SESSIONS, JSON.stringify(arr.slice(0,50))); } catch {}
  }
  function _lsGetMsgs(sid) {
    try { return JSON.parse(localStorage.getItem(LS_KEY_MSGS(sid)) || '[]'); } catch { return []; }
  }
  function _lsSetMsgs(sid, msgs) {
    try { localStorage.setItem(LS_KEY_MSGS(sid), JSON.stringify(msgs.slice(-200))); } catch {}
  }
  function _lsAddMsg(sid, msg) {
    const msgs = _lsGetMsgs(sid);
    msgs.push(msg);
    _lsSetMsgs(sid, msgs);
  }

  // ── API client ────────────────────────────────────────────────────────────
  async function _api(method, path, body, opts = {}) {
    const url = `${RAKAY.apiBase}/api/RAKAY${path}`;
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };

    // Attach auth token if available
    const token = (typeof window.authFetch !== 'undefined') ? null
      : (localStorage.getItem('wadjet_token') || localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token'));
    if (token) headers['Authorization'] = `Bearer ${token}`;

    if (typeof window.authFetch === 'function' && !opts.noAuthFetch) {
      // Use platform auth interceptor when available
      try {
        const res  = await window.authFetch(path.startsWith('/') ? `/api/RAKAY${path}` : path, {
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined,
        });
        if (!res.ok && res.status === 404) return null;
        return await res.json();
      } catch (err) {
        if (err?.message?.includes('network') || err?.message?.includes('fetch')) {
          RAKAY.backendOnline = false;
        }
        throw err;
      }
    }

    // Direct fetch fallback
    const res = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    RAKAY.backendOnline = true;
    if (!res.ok && res.status === 404) return null;
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  }

  // ── Session management (online + offline) ─────────────────────────────────
  async function _loadSessions() {
    try {
      const data = await _api('GET', '/session');
      if (data?.sessions) {
        RAKAY.sessions = data.sessions;
        // Sync to localStorage as backup
        _lsSetSessions(RAKAY.sessions);
        return;
      }
    } catch { /* backend offline */ }

    // Fallback: localStorage
    RAKAY.sessions = _lsGetSessions();
    RAKAY.backendOnline = false;
  }

  async function _createSession(title = 'New Chat') {
    // Optimistic local creation
    const local = { id: _uid(), title, message_count: 0, tokens_used: 0, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), _local: true };

    try {
      const data = await _api('POST', '/session', { title });
      if (data?.session) {
        RAKAY.sessions.unshift(data.session);
        _lsSetSessions(RAKAY.sessions);
        return data.session;
      }
    } catch { /* backend offline */ }

    // Use local session
    RAKAY.sessions.unshift(local);
    _lsSetSessions(RAKAY.sessions);
    return local;
  }

  async function _deleteSession(sid) {
    RAKAY.sessions = RAKAY.sessions.filter(s => s.id !== sid);
    _lsSetSessions(RAKAY.sessions);
    try { await _api('DELETE', `/session/${sid}`); } catch {}
  }

  async function _renameSession(sid, title) {
    const s = RAKAY.sessions.find(s => s.id === sid);
    if (s) { s.title = title; _lsSetSessions(RAKAY.sessions); }
    try { await _api('PATCH', `/session/${sid}`, { title }); } catch {}
  }

  async function _loadHistory(sid) {
    try {
      const data = await _api('GET', `/history/${sid}`);
      if (data?.messages) {
        RAKAY.messages = data.messages;
        _lsSetMsgs(sid, RAKAY.messages);
        return;
      }
    } catch {}
    RAKAY.messages = _lsGetMsgs(sid);
  }

  // ── Chat API ──────────────────────────────────────────────────────────────
  async function _sendMessage(message) {
    if (!message.trim() || RAKAY.loading) return;

    const userMsg = {
      id:         _uid(),
      session_id: RAKAY.sessionId,
      role:       'user',
      content:    message.trim(),
      created_at: new Date().toISOString(),
    };

    RAKAY.messages.push(userMsg);
    RAKAY.loading = true;
    _renderMessages();
    _setInputEnabled(false);
    _showTyping();

    // Save user message locally
    _lsAddMsg(RAKAY.sessionId, userMsg);

    // Update session title if first message
    const session = RAKAY.sessions.find(s => s.id === RAKAY.sessionId);
    if (session && session.message_count === 0) {
      const title = message.trim().slice(0, 60);
      session.title = title;
      _lsSetSessions(RAKAY.sessions);
      _renderSidebar();
    }

    try {
      const context = {
        currentPage: window.currentPage || 'rakay',
        platform_context: { page: window.currentPage },
      };

      const data = await _api('POST', '/chat', {
        session_id:  RAKAY.sessionId,
        message:     message.trim(),
        context,
        use_tools:   true,
      });

      _hideTyping();

      if (data) {
        const assistantMsg = {
          id:          data.id || _uid(),
          session_id:  RAKAY.sessionId,
          role:        'assistant',
          content:     data.content || '',
          tool_trace:  data.tool_trace || [],
          tokens_used: data.tokens_used || 0,
          model:       data.model,
          latency_ms:  data.latency_ms,
          created_at:  data.created_at || new Date().toISOString(),
        };

        RAKAY.messages.push(assistantMsg);
        _lsAddMsg(RAKAY.sessionId, assistantMsg);

        // Update session stats
        if (session) {
          session.message_count = (session.message_count || 0) + 2;
          session.updated_at    = new Date().toISOString();
          _lsSetSessions(RAKAY.sessions);
        }

        _renderMessages();
        _renderSidebar();
        _scrollToBottom();
      } else {
        _appendError('No response from RAKAY. The backend may be offline.');
      }
    } catch (err) {
      _hideTyping();
      const isOffline = err.message?.includes('fetch') || err.message?.includes('network') || !navigator.onLine;
      if (isOffline || RAKAY.backendOnline === false) {
        _appendLocalResponse(message);
      } else {
        _appendError(`RAKAY error: ${err.message}`);
      }
    } finally {
      RAKAY.loading = false;
      _setInputEnabled(true);
      _focusInput();
    }
  }

  // ── Offline/local response (when backend unavailable) ─────────────────────
  function _appendLocalResponse(query) {
    const lower = query.toLowerCase();
    let content = '';

    if (lower.includes('sigma')) {
      content = '**Note**: Backend offline. Here\'s a quick Sigma rule template:\n\n```yaml\ntitle: Detect Suspicious Activity\nstatus: experimental\ndescription: Detects suspicious process creation\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - suspicious_keyword\n  condition: selection\nlevel: high\n```\n\n*Connect to the backend for full AI-generated rules.*';
    } else if (lower.includes('mitre') || lower.match(/t\d{4}/i)) {
      content = '**Note**: Backend offline. Visit [MITRE ATT&CK](https://attack.mitre.org) for technique details, or reconnect the backend for AI-powered lookups.';
    } else if (lower.includes('cve')) {
      content = '**Note**: Backend offline. Search [NVD](https://nvd.nist.gov) for CVE details, or reconnect the backend.';
    } else {
      content = '**RAKAY is offline** — the backend server is not reachable.\n\nTo use RAKAY\'s full AI capabilities:\n1. Ensure the backend is running at `https://wadjet-eye-ai.onrender.com`\n2. Or set `window.THREATPILOT_API_URL` to your local backend\n3. Check your authentication token\n\nLocal platform features remain fully functional.';
    }

    const msg = { id: _uid(), session_id: RAKAY.sessionId, role: 'assistant', content, created_at: new Date().toISOString(), _offline: true };
    RAKAY.messages.push(msg);
    _lsAddMsg(RAKAY.sessionId, msg);
    _renderMessages();
    _scrollToBottom();
  }

  function _appendError(text) {
    const errEl = document.querySelector('#rakay-messages .rakay-error-msg');
    if (errEl) errEl.remove();
    const el = document.createElement('div');
    el.className = 'rakay-error-msg';
    el.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${_e(text)}`;
    const container = document.getElementById('rakay-messages');
    if (container) container.appendChild(el);
    _scrollToBottom();
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  MARKDOWN RENDERER
  // ══════════════════════════════════════════════════════════════════════════
  function _renderMarkdown(text) {
    if (!text) return '';

    // Use marked.js if loaded
    if (typeof window.marked !== 'undefined') {
      try {
        return window.marked.parse(text, { breaks: true, gfm: true });
      } catch {}
    }

    // Custom lightweight markdown renderer
    let html = _e(text);

    // Fenced code blocks with syntax highlighting class
    html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, (_, lang, code) => {
      const langClass = lang ? ` class="language-${_e(lang)}"` : '';
      const langLabel = lang ? `<span class="rakay-code-lang">${_e(lang)}</span>` : '';
      const copyBtn   = `<button class="rakay-copy-btn" onclick="window._rakayCopyCode(this)" title="Copy"><i class="fas fa-copy"></i></button>`;
      return `<div class="rakay-code-wrap">${langLabel}${copyBtn}<pre><code${langClass}>${code.trim()}</code></pre></div>`;
    });

    // Inline code
    html = html.replace(/`([^`\n]+)`/g, '<code class="rakay-inline-code">$1</code>');

    // Headers
    html = html.replace(/^### (.+)$/gm, '<h3 class="rakay-h3">$1</h3>');
    html = html.replace(/^## (.+)$/gm,  '<h2 class="rakay-h2">$1</h2>');
    html = html.replace(/^# (.+)$/gm,   '<h1 class="rakay-h1">$1</h1>');

    // Bold + italic
    html = html.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.+?)\*/g,     '<em>$1</em>');
    html = html.replace(/_(.+?)_/g,       '<em>$1</em>');

    // Tables
    html = html.replace(/(?:^|\n)((?:\|[^\n]+\|\n)+)/g, (_, table) => {
      const rows = table.trim().split('\n').filter(r => r.trim());
      if (rows.length < 2) return _ ;
      const sep = rows[1];
      if (!sep.match(/^\|[-| :]+\|$/)) return _;
      const headers = rows[0].split('|').slice(1,-1).map(h => `<th>${h.trim()}</th>`).join('');
      const body    = rows.slice(2).map(r => `<tr>${r.split('|').slice(1,-1).map(c => `<td>${c.trim()}</td>`).join('')}</tr>`).join('');
      return `<div class="rakay-table-wrap"><table class="rakay-table"><thead><tr>${headers}</tr></thead><tbody>${body}</tbody></table></div>`;
    });

    // Unordered list
    html = html.replace(/((?:^- .+\n?)+)/gm, match => {
      const items = match.trim().split('\n').map(l => `<li>${l.replace(/^- /, '')}</li>`).join('');
      return `<ul class="rakay-ul">${items}</ul>`;
    });

    // Ordered list
    html = html.replace(/((?:^\d+\. .+\n?)+)/gm, match => {
      const items = match.trim().split('\n').map(l => `<li>${l.replace(/^\d+\. /, '')}</li>`).join('');
      return `<ol class="rakay-ol">${items}</ol>`;
    });

    // Blockquote
    html = html.replace(/^&gt; (.+)$/gm, '<blockquote class="rakay-blockquote">$1</blockquote>');

    // Horizontal rule
    html = html.replace(/^---+$/gm, '<hr class="rakay-hr">');

    // Links
    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g,
      '<a href="$2" target="_blank" rel="noopener" class="rakay-link">$1 <i class="fas fa-external-link-alt" style="font-size:9px"></i></a>');

    // Paragraphs (double newline)
    html = html.replace(/\n\n/g, '</p><p>');
    html = `<p>${html}</p>`;
    html = html.replace(/<p>\s*<\/p>/g, '');

    // Single newline → line break
    html = html.replace(/\n/g, '<br>');

    // Clean up redundant p around block elements
    html = html.replace(/<p>(<(?:h[123]|ul|ol|div|pre|table|blockquote|hr)[^>]*>)/g, '$1');
    html = html.replace(/<\/(?:h[123]|ul|ol|div|pre|table|blockquote)><\/p>/g, (m) => m.replace('</p>', ''));

    return html;
  }

  // ── Global copy helper ────────────────────────────────────────────────────
  window._rakayCopyCode = function(btn) {
    const code = btn.closest('.rakay-code-wrap')?.querySelector('code')?.textContent || '';
    navigator.clipboard.writeText(code).then(() => {
      btn.innerHTML = '<i class="fas fa-check"></i>';
      setTimeout(() => { btn.innerHTML = '<i class="fas fa-copy"></i>'; }, 2000);
    });
  };

  // ══════════════════════════════════════════════════════════════════════════
  //  TOOL TRACE VISUALISER
  // ══════════════════════════════════════════════════════════════════════════
  function _renderToolTrace(trace) {
    if (!trace || !trace.length) return '';

    const iconMap = {
      sigma_search:       'fa-search',
      sigma_generate:     'fa-file-code',
      kql_generate:       'fa-terminal',
      ioc_enrich:         'fa-shield-alt',
      mitre_lookup:       'fa-sitemap',
      cve_lookup:         'fa-bug',
      threat_actor_profile: 'fa-user-secret',
      platform_navigate:  'fa-compass',
    };

    const items = trace.map((t, i) => {
      const icon    = iconMap[t.tool] || 'fa-cog';
      const traceId = `rakay-trace-${Date.now()}-${i}`;
      const hasResult = t.result && typeof t.result === 'object';

      return `
      <div class="rakay-tool-item">
        <div class="rakay-tool-header" onclick="document.getElementById('${traceId}').classList.toggle('open')">
          <span class="rakay-tool-icon"><i class="fas ${icon}"></i></span>
          <span class="rakay-tool-name">${_e(t.tool.replace(/_/g,' '))}</span>
          <span class="rakay-tool-args">${_e(JSON.stringify(t.args || {}).slice(0,80))}</span>
          <span class="rakay-tool-chevron"><i class="fas fa-chevron-down"></i></span>
        </div>
        <div class="rakay-tool-body" id="${traceId}">
          ${hasResult ? `<pre class="rakay-tool-result">${_e(JSON.stringify(t.result, null, 2).slice(0, 2000))}</pre>` : '<span style="color:#8b949e">No result data</span>'}
        </div>
      </div>`;
    });

    return `
    <div class="rakay-tool-trace">
      <div class="rakay-tool-trace-header" onclick="this.nextElementSibling.classList.toggle('open')">
        <i class="fas fa-wrench" style="color:#22d3ee;margin-right:6px"></i>
        <span>${trace.length} tool${trace.length>1?'s':''} used</span>
        <i class="fas fa-chevron-down" style="margin-left:auto"></i>
      </div>
      <div class="rakay-tool-trace-body">
        ${items.join('')}
      </div>
    </div>`;
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  RENDER FUNCTIONS
  // ══════════════════════════════════════════════════════════════════════════

  function _renderMessages() {
    const container = document.getElementById('rakay-messages');
    if (!container) return;

    if (!RAKAY.messages.length) {
      container.innerHTML = _renderWelcome();
      return;
    }

    const items = RAKAY.messages.map(msg => {
      const isUser = msg.role === 'user';
      const ts     = _time(msg.created_at);
      const trace  = msg.tool_trace ? _renderToolTrace(msg.tool_trace) : '';
      const offline = msg._offline ? ' rakay-msg--offline' : '';

      if (isUser) {
        return `
        <div class="rakay-msg rakay-msg--user${offline}">
          <div class="rakay-msg-content">
            <div class="rakay-msg-bubble rakay-msg-bubble--user">${_e(msg.content)}</div>
            <div class="rakay-msg-meta">${ts}</div>
          </div>
          <div class="rakay-msg-avatar rakay-msg-avatar--user">
            <i class="fas fa-user"></i>
          </div>
        </div>`;
      }

      const modelBadge = msg.model ? `<span class="rakay-model-badge">${_e(msg.model)}</span>` : '';
      const latency    = msg.latency_ms ? `<span class="rakay-latency">${msg.latency_ms}ms</span>` : '';
      const tokens     = msg.tokens_used ? `<span class="rakay-tokens"><i class="fas fa-bolt"></i> ${msg.tokens_used}</span>` : '';

      return `
      <div class="rakay-msg rakay-msg--assistant${offline}">
        <div class="rakay-msg-avatar rakay-msg-avatar--assistant">
          <i class="fas fa-robot"></i>
        </div>
        <div class="rakay-msg-content">
          ${trace}
          <div class="rakay-msg-bubble rakay-msg-bubble--assistant">
            ${_renderMarkdown(msg.content)}
          </div>
          <div class="rakay-msg-meta">${ts} ${modelBadge} ${latency} ${tokens}</div>
        </div>
      </div>`;
    }).join('');

    container.innerHTML = items;

    // Syntax highlight if Prism/hljs loaded
    if (typeof window.Prism !== 'undefined') {
      container.querySelectorAll('pre code').forEach(el => window.Prism.highlightElement(el));
    } else if (typeof window.hljs !== 'undefined') {
      container.querySelectorAll('pre code').forEach(el => window.hljs.highlightElement(el));
    }
  }

  function _renderWelcome() {
    return `
    <div class="rakay-welcome">
      <div class="rakay-welcome-logo">
        <i class="fas fa-robot"></i>
      </div>
      <h2 class="rakay-welcome-title">RAKAY — AI Security Analyst</h2>
      <p class="rakay-welcome-sub">Powered by Wadjet-Eye AI Platform</p>
      <div class="rakay-welcome-prompts">
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-file-code"></i> Generate Sigma rule for PowerShell encoded commands
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-sitemap"></i> Explain MITRE ATT&CK T1059.001
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-terminal"></i> Create KQL query for ransomware detection
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-user-secret"></i> Profile the APT29 threat group
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-shield-alt"></i> Enrich IP 185.220.101.34
        </button>
        <button class="rakay-prompt-chip" onclick="window._rakayQuickPrompt(this)">
          <i class="fas fa-bug"></i> What is CVE-2024-12356?
        </button>
      </div>
    </div>`;
  }

  function _renderSidebar() {
    const list = document.getElementById('rakay-session-list');
    if (!list) return;

    if (!RAKAY.sessions.length) {
      list.innerHTML = '<div class="rakay-session-empty">No sessions yet.<br>Start a new chat.</div>';
      return;
    }

    list.innerHTML = RAKAY.sessions.map(s => {
      const active = s.id === RAKAY.sessionId ? ' rakay-session--active' : '';
      const msgCnt = s.message_count ? `<span class="rakay-session-cnt">${s.message_count}</span>` : '';
      return `
      <div class="rakay-session-item${active}" data-sid="${_e(s.id)}" onclick="window._rakaySelectSession('${_e(s.id)}')">
        <div class="rakay-session-title" title="${_e(s.title)}">${_e(s.title || 'Chat')}</div>
        <div class="rakay-session-meta">${_time(s.updated_at)} ${msgCnt}</div>
        <div class="rakay-session-actions">
          <button class="rakay-session-btn" onclick="event.stopPropagation();window._rakayRenameSession('${_e(s.id)}')" title="Rename"><i class="fas fa-pen"></i></button>
          <button class="rakay-session-btn rakay-session-btn--del" onclick="event.stopPropagation();window._rakayDeleteSession('${_e(s.id)}')" title="Delete"><i class="fas fa-trash"></i></button>
        </div>
      </div>`;
    }).join('');
  }

  function _showTyping() {
    RAKAY.typing = true;
    const container = document.getElementById('rakay-messages');
    if (!container) return;

    // Remove any existing typing indicator
    const existing = container.querySelector('.rakay-typing-indicator');
    if (existing) existing.remove();

    const el = document.createElement('div');
    el.className = 'rakay-msg rakay-msg--assistant rakay-typing-indicator';
    el.innerHTML = `
    <div class="rakay-msg-avatar rakay-msg-avatar--assistant">
      <i class="fas fa-robot"></i>
    </div>
    <div class="rakay-msg-content">
      <div class="rakay-msg-bubble rakay-msg-bubble--assistant">
        <div class="rakay-typing-dots">
          <span></span><span></span><span></span>
        </div>
        <span class="rakay-typing-label">RAKAY is thinking…</span>
      </div>
    </div>`;
    container.appendChild(el);
    _scrollToBottom();
  }

  function _hideTyping() {
    RAKAY.typing = false;
    const indicator = document.querySelector('.rakay-typing-indicator');
    if (indicator) indicator.remove();
  }

  function _setInputEnabled(enabled) {
    const inp = document.getElementById('rakay-input');
    const btn = document.getElementById('rakay-send');
    if (inp) inp.disabled = !enabled;
    if (btn) btn.disabled = !enabled;
    if (btn) btn.innerHTML = enabled
      ? '<i class="fas fa-paper-plane"></i>'
      : '<i class="fas fa-circle-notch fa-spin"></i>';
  }

  function _focusInput() {
    const inp = document.getElementById('rakay-input');
    if (inp) inp.focus();
  }

  function _scrollToBottom(smooth = true) {
    const container = document.getElementById('rakay-messages');
    if (container) {
      container.scrollTo({ top: container.scrollHeight, behavior: smooth ? 'smooth' : 'instant' });
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  GLOBAL INTERACTION HANDLERS
  // ══════════════════════════════════════════════════════════════════════════

  window._rakayQuickPrompt = function(btn) {
    const text = btn.textContent.trim().replace(/^\S+\s+/, ''); // strip icon char
    const inp  = document.getElementById('rakay-input');
    if (inp) { inp.value = text; inp.focus(); _autoResize(inp); }
  };

  window._rakaySelectSession = async function(sid) {
    if (sid === RAKAY.sessionId) return;
    RAKAY.sessionId = sid;
    RAKAY.messages  = [];
    _renderMessages();
    _renderSidebar();
    await _loadHistory(sid);
    _renderMessages();
    _scrollToBottom(false);
    _focusInput();
    _updateHeader();
  };

  window._rakayDeleteSession = async function(sid) {
    const session = RAKAY.sessions.find(s => s.id === sid);
    const name    = session?.title || 'this chat';
    if (!confirm(`Delete "${name}"? This action cannot be undone.`)) return;

    await _deleteSession(sid);

    if (RAKAY.sessionId === sid) {
      // Switch to another session or create new
      if (RAKAY.sessions.length) {
        await window._rakaySelectSession(RAKAY.sessions[0].id);
      } else {
        await _startNewChat();
      }
    }
    _renderSidebar();
  };

  window._rakayRenameSession = function(sid) {
    const session = RAKAY.sessions.find(s => s.id === sid);
    if (!session) return;
    const newTitle = prompt('Rename session:', session.title || 'Chat');
    if (newTitle && newTitle.trim()) {
      _renameSession(sid, newTitle.trim().slice(0, 120));
      _renderSidebar();
      if (sid === RAKAY.sessionId) _updateHeader();
    }
  };

  window._rakayNewChat = async function() {
    await _startNewChat();
  };

  window._rakaySubmit = function() {
    const inp = document.getElementById('rakay-input');
    if (!inp) return;
    const msg = inp.value.trim();
    if (!msg) return;
    inp.value = '';
    _autoResize(inp);
    _sendMessage(msg);
  };

  window._rakaySearchSessions = function(q) {
    const items = document.querySelectorAll('.rakay-session-item');
    items.forEach(item => {
      const title = item.querySelector('.rakay-session-title')?.textContent.toLowerCase() || '';
      item.style.display = (!q || title.includes(q.toLowerCase())) ? '' : 'none';
    });
  };

  window._rakayClearSearch = function() {
    const inp = document.getElementById('rakay-session-search');
    if (inp) { inp.value = ''; window._rakaySearchSessions(''); }
  };

  // ── Auto-resize textarea ──────────────────────────────────────────────────
  function _autoResize(el) {
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 200) + 'px';
  }

  function _updateHeader() {
    const title = document.getElementById('rakay-current-title');
    if (!title) return;
    const s = RAKAY.sessions.find(s => s.id === RAKAY.sessionId);
    title.textContent = s?.title || 'RAKAY';
  }

  async function _startNewChat() {
    const session  = await _createSession();
    RAKAY.sessionId = session.id;
    RAKAY.messages  = [];
    _renderSidebar();
    _renderMessages();
    _updateHeader();
    _focusInput();
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  CSS INJECTION
  // ══════════════════════════════════════════════════════════════════════════
  function _injectCSS() {
    if (document.getElementById('rakay-styles')) return;
    const style = document.createElement('style');
    style.id = 'rakay-styles';
    style.textContent = `
/* ═══════════════════════════════════════
   RAKAY Module Styles — Wadjet-Eye AI
═══════════════════════════════════════ */
.rakay-root {
  display: flex;
  height: calc(100vh - 70px);
  max-height: 100%;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  background: var(--bg-primary, #0d1117);
  color: var(--text-primary, #e6edf3);
  overflow: hidden;
}

/* ── Sidebar ─────────────────────────────── */
.rakay-sidebar {
  width: 260px;
  min-width: 220px;
  max-width: 300px;
  background: var(--bg-secondary, #161b22);
  border-right: 1px solid var(--border, #30363d);
  display: flex;
  flex-direction: column;
  gap: 0;
  overflow: hidden;
  transition: width .2s;
}
.rakay-sidebar-header {
  padding: 16px 14px 12px;
  border-bottom: 1px solid var(--border, #30363d);
  display: flex;
  align-items: center;
  gap: 8px;
}
.rakay-sidebar-logo {
  width: 32px; height: 32px;
  background: linear-gradient(135deg, #22d3ee22, #a855f722);
  border: 1px solid #22d3ee44;
  border-radius: 8px;
  display: flex; align-items: center; justify-content: center;
  color: #22d3ee; font-size: 14px;
  flex-shrink: 0;
}
.rakay-sidebar-title {
  font-size: 15px; font-weight: 600; color: #e6edf3;
  flex: 1;
}
.rakay-new-btn {
  background: none; border: 1px solid #30363d; color: #22d3ee;
  border-radius: 6px; padding: 5px 8px; cursor: pointer; font-size: 12px;
  transition: all .15s;
}
.rakay-new-btn:hover { background: #22d3ee22; border-color: #22d3ee44; }
.rakay-session-search-wrap {
  padding: 10px 12px 6px;
  border-bottom: 1px solid var(--border, #30363d);
}
.rakay-session-search {
  width: 100%; padding: 6px 10px; box-sizing: border-box;
  background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
  color: #e6edf3; font-size: 12px; outline: none;
}
.rakay-session-search:focus { border-color: #22d3ee44; }
.rakay-session-list {
  flex: 1; overflow-y: auto; padding: 6px 8px;
}
.rakay-session-list::-webkit-scrollbar { width: 4px; }
.rakay-session-list::-webkit-scrollbar-track { background: transparent; }
.rakay-session-list::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }
.rakay-session-item {
  padding: 8px 10px; border-radius: 8px; cursor: pointer;
  position: relative; display: flex; flex-direction: column; gap: 3px;
  transition: background .12s;
  border: 1px solid transparent;
}
.rakay-session-item:hover { background: #21262d; border-color: #30363d; }
.rakay-session-item.rakay-session--active { background: #22d3ee12; border-color: #22d3ee30; }
.rakay-session-title { font-size: 13px; font-weight: 500; color: #c9d1d9; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 200px; }
.rakay-session-meta { font-size: 11px; color: #8b949e; display: flex; align-items: center; gap: 6px; }
.rakay-session-cnt { background: #22d3ee22; color: #22d3ee; padding: 1px 5px; border-radius: 10px; font-size: 10px; }
.rakay-session-actions {
  position: absolute; right: 8px; top: 50%; transform: translateY(-50%);
  display: none; gap: 4px;
}
.rakay-session-item:hover .rakay-session-actions { display: flex; }
.rakay-session-btn {
  background: none; border: none; color: #8b949e; cursor: pointer;
  padding: 3px 5px; border-radius: 4px; font-size: 11px;
  transition: all .12s;
}
.rakay-session-btn:hover { background: #21262d; color: #c9d1d9; }
.rakay-session-btn--del:hover { color: #f85149; background: #f8514920; }
.rakay-session-empty { color: #8b949e; font-size: 12px; text-align: center; padding: 20px 10px; line-height: 1.6; }

/* ── Main chat area ──────────────────────── */
.rakay-main {
  flex: 1; display: flex; flex-direction: column; overflow: hidden;
}
.rakay-header {
  padding: 14px 20px;
  border-bottom: 1px solid var(--border, #30363d);
  display: flex; align-items: center; gap: 12px;
  background: var(--bg-secondary, #161b22);
  flex-shrink: 0;
}
.rakay-header-icon {
  width: 36px; height: 36px;
  background: linear-gradient(135deg, #22d3ee20, #a855f720);
  border: 1px solid #22d3ee40;
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  color: #22d3ee; font-size: 16px;
}
.rakay-header-info { flex: 1; }
.rakay-header-title { font-size: 15px; font-weight: 600; color: #e6edf3; }
.rakay-header-sub { font-size: 11px; color: #8b949e; }
.rakay-status-dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: #3fb950; box-shadow: 0 0 0 2px #3fb95030;
}
.rakay-status-dot.offline { background: #f85149; box-shadow: 0 0 0 2px #f8514930; }

/* ── Messages ────────────────────────────── */
#rakay-messages {
  flex: 1; overflow-y: auto; padding: 20px 24px;
  display: flex; flex-direction: column; gap: 20px;
}
#rakay-messages::-webkit-scrollbar { width: 5px; }
#rakay-messages::-webkit-scrollbar-track { background: transparent; }
#rakay-messages::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }

.rakay-msg { display: flex; gap: 12px; max-width: 100%; animation: rakayFadeIn .2s ease; }
@keyframes rakayFadeIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
.rakay-msg--user { flex-direction: row-reverse; }
.rakay-msg-avatar {
  width: 36px; height: 36px; border-radius: 10px; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center; font-size: 14px;
}
.rakay-msg-avatar--assistant { background: linear-gradient(135deg,#22d3ee20,#a855f720); border: 1px solid #22d3ee30; color: #22d3ee; }
.rakay-msg-avatar--user       { background: linear-gradient(135deg,#3b82f620,#6366f120); border: 1px solid #3b82f630; color: #60a5fa; }
.rakay-msg-content { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 6px; }
.rakay-msg--user .rakay-msg-content { align-items: flex-end; }
.rakay-msg-bubble {
  padding: 12px 16px; border-radius: 12px; max-width: 90%;
  line-height: 1.6; font-size: 14px; word-wrap: break-word;
}
.rakay-msg-bubble--assistant {
  background: var(--bg-secondary, #161b22);
  border: 1px solid var(--border, #30363d);
  border-radius: 12px 12px 12px 2px;
}
.rakay-msg-bubble--user {
  background: linear-gradient(135deg, #1d4ed820, #2563eb20);
  border: 1px solid #3b82f630;
  border-radius: 12px 12px 2px 12px;
  color: #c9d1d9;
}
.rakay-msg-meta { font-size: 11px; color: #8b949e; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.rakay-model-badge { background: #a855f720; color: #a855f7; padding: 1px 6px; border-radius: 10px; font-size: 10px; }
.rakay-latency { color: #8b949e; font-size: 10px; }
.rakay-tokens { color: #22d3ee; font-size: 10px; display: flex; align-items: center; gap: 3px; }

/* ── Typing indicator ────────────────────── */
.rakay-typing-dots { display: flex; gap: 4px; align-items: center; margin-bottom: 4px; }
.rakay-typing-dots span {
  width: 6px; height: 6px; background: #22d3ee; border-radius: 50%;
  animation: rakayDot 1.2s infinite;
}
.rakay-typing-dots span:nth-child(2) { animation-delay: .2s; }
.rakay-typing-dots span:nth-child(3) { animation-delay: .4s; }
@keyframes rakayDot { 0%,80%,100%{transform:scale(.6);opacity:.4} 40%{transform:scale(1);opacity:1} }
.rakay-typing-label { font-size: 12px; color: #8b949e; }

/* ── Tool trace ──────────────────────────── */
.rakay-tool-trace {
  border: 1px solid #22d3ee30;
  border-radius: 8px; overflow: hidden; margin-bottom: 6px;
  background: #0d111780;
}
.rakay-tool-trace-header {
  padding: 8px 12px; display: flex; align-items: center; gap: 8px;
  cursor: pointer; font-size: 12px; color: #8b949e;
  background: #22d3ee08; border-bottom: 1px solid #22d3ee20;
  transition: background .12s;
}
.rakay-tool-trace-header:hover { background: #22d3ee14; }
.rakay-tool-trace-body { display: none; }
.rakay-tool-trace-body.open { display: block; }
.rakay-tool-item { border-bottom: 1px solid #30363d; }
.rakay-tool-item:last-child { border-bottom: none; }
.rakay-tool-header {
  padding: 8px 12px; display: flex; align-items: center; gap: 8px;
  cursor: pointer; font-size: 12px; transition: background .12s;
}
.rakay-tool-header:hover { background: #21262d; }
.rakay-tool-icon { color: #22d3ee; width: 18px; text-align: center; }
.rakay-tool-name { font-weight: 500; color: #c9d1d9; text-transform: capitalize; }
.rakay-tool-args { color: #8b949e; font-size: 11px; flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.rakay-tool-chevron { color: #8b949e; font-size: 10px; margin-left: auto; }
.rakay-tool-body { display: none; padding: 0 12px 10px; }
.rakay-tool-body.open { display: block; }
.rakay-tool-result { font-size: 11px; color: #8b949e; background: #0d1117; padding: 8px; border-radius: 6px; overflow-x: auto; max-height: 300px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }

/* ── Markdown styles ─────────────────────── */
.rakay-msg-bubble p { margin: 0 0 .6em; }
.rakay-msg-bubble p:last-child { margin-bottom: 0; }
.rakay-h1,.rakay-h2,.rakay-h3 { color: #e6edf3; margin: .8em 0 .4em; font-weight: 600; }
.rakay-h1 { font-size: 1.3em; }
.rakay-h2 { font-size: 1.15em; }
.rakay-h3 { font-size: 1.05em; }
.rakay-code-wrap { position: relative; margin: .6em 0; border-radius: 8px; overflow: hidden; background: #0d1117; border: 1px solid #30363d; }
.rakay-code-wrap pre { margin: 0; padding: 14px; overflow-x: auto; }
.rakay-code-wrap code { font-family: 'JetBrains Mono','Fira Code','Consolas',monospace; font-size: 12px; color: #c9d1d9; }
.rakay-code-lang { position: absolute; top: 6px; left: 10px; font-size: 10px; color: #8b949e; text-transform: uppercase; letter-spacing: .05em; }
.rakay-copy-btn {
  position: absolute; top: 6px; right: 8px;
  background: #21262d; border: 1px solid #30363d; border-radius: 4px;
  color: #8b949e; cursor: pointer; padding: 3px 6px; font-size: 11px;
  transition: all .12s; z-index: 1;
}
.rakay-copy-btn:hover { background: #30363d; color: #c9d1d9; }
.rakay-inline-code { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 1px 5px; font-family: monospace; font-size: 12px; color: #f0883e; }
.rakay-ul,.rakay-ol { padding-left: 1.4em; margin: .5em 0; }
.rakay-ul li,.rakay-ol li { margin: .2em 0; }
.rakay-table-wrap { overflow-x: auto; margin: .6em 0; }
.rakay-table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
.rakay-table th { background: #21262d; color: #c9d1d9; padding: 7px 12px; border: 1px solid #30363d; text-align: left; }
.rakay-table td { padding: 6px 12px; border: 1px solid #21262d; color: #8b949e; }
.rakay-table tr:hover td { background: #161b22; }
.rakay-blockquote { border-left: 3px solid #22d3ee; padding: 4px 12px; margin: .5em 0; color: #8b949e; font-style: italic; background: #22d3ee08; border-radius: 0 6px 6px 0; }
.rakay-hr { border: none; border-top: 1px solid #30363d; margin: .8em 0; }
.rakay-link { color: #22d3ee; text-decoration: none; }
.rakay-link:hover { text-decoration: underline; }

/* ── Input area ──────────────────────────── */
.rakay-input-area {
  padding: 14px 20px;
  border-top: 1px solid var(--border, #30363d);
  background: var(--bg-secondary, #161b22);
  flex-shrink: 0;
}
.rakay-input-wrap {
  display: flex; align-items: flex-end; gap: 10px;
  background: var(--bg-primary, #0d1117);
  border: 1px solid var(--border, #30363d);
  border-radius: 12px; padding: 10px 14px;
  transition: border-color .15s;
}
.rakay-input-wrap:focus-within { border-color: #22d3ee50; }
#rakay-input {
  flex: 1; background: none; border: none; outline: none; resize: none;
  color: #e6edf3; font-size: 14px; font-family: inherit;
  line-height: 1.5; max-height: 200px; min-height: 22px; overflow-y: auto;
}
#rakay-input::placeholder { color: #8b949e; }
#rakay-send {
  background: linear-gradient(135deg, #22d3ee, #0ea5e9);
  border: none; border-radius: 8px; color: #fff; cursor: pointer;
  width: 36px; height: 36px; display: flex; align-items: center; justify-content: center;
  font-size: 14px; flex-shrink: 0; transition: opacity .15s;
}
#rakay-send:hover:not(:disabled) { opacity: .85; }
#rakay-send:disabled { opacity: .4; cursor: not-allowed; }
.rakay-input-hint { font-size: 11px; color: #8b949e; margin-top: 6px; display: flex; align-items: center; gap: 6px; }

/* ── Welcome screen ──────────────────────── */
.rakay-welcome {
  flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center;
  padding: 40px 20px; text-align: center; gap: 16px;
}
.rakay-welcome-logo {
  width: 64px; height: 64px;
  background: linear-gradient(135deg, #22d3ee20, #a855f720);
  border: 1px solid #22d3ee40; border-radius: 16px;
  display: flex; align-items: center; justify-content: center;
  font-size: 28px; color: #22d3ee;
}
.rakay-welcome-title { font-size: 22px; font-weight: 700; color: #e6edf3; margin: 0; }
.rakay-welcome-sub { font-size: 14px; color: #8b949e; margin: 0; }
.rakay-welcome-prompts { display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; max-width: 680px; margin-top: 8px; }
.rakay-prompt-chip {
  background: var(--bg-secondary, #161b22);
  border: 1px solid var(--border, #30363d);
  border-radius: 8px; padding: 8px 14px; cursor: pointer;
  font-size: 13px; color: #8b949e; transition: all .15s;
  display: flex; align-items: center; gap: 7px;
}
.rakay-prompt-chip:hover { background: #21262d; border-color: #22d3ee40; color: #c9d1d9; }
.rakay-prompt-chip i { color: #22d3ee; }

/* ── Error message ───────────────────────── */
.rakay-error-msg {
  background: #f8514914; border: 1px solid #f8514940;
  color: #f85149; border-radius: 8px; padding: 10px 14px; font-size: 13px;
  display: flex; align-items: center; gap: 8px;
}
.rakay-msg--offline .rakay-msg-bubble--assistant { border-color: #f0883e30; }

/* ── Responsive ──────────────────────────── */
@media (max-width: 680px) {
  .rakay-sidebar { width: 0; min-width: 0; overflow: hidden; }
  .rakay-sidebar.open { width: 260px; }
}
`;
    document.head.appendChild(style);
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  PAGE HTML BUILDER
  // ══════════════════════════════════════════════════════════════════════════
  function _buildHTML() {
    return `
<div class="rakay-root" id="rakay-root">

  <!-- Sidebar -->
  <aside class="rakay-sidebar" id="rakay-sidebar">
    <div class="rakay-sidebar-header">
      <div class="rakay-sidebar-logo"><i class="fas fa-robot"></i></div>
      <span class="rakay-sidebar-title">RAKAY</span>
      <button class="rakay-new-btn" onclick="window._rakayNewChat()" title="New chat">
        <i class="fas fa-plus"></i>
      </button>
    </div>

    <div class="rakay-session-search-wrap">
      <input
        type="text"
        id="rakay-session-search"
        class="rakay-session-search"
        placeholder="Search sessions…"
        oninput="window._rakaySearchSessions(this.value)"
      >
    </div>

    <div class="rakay-session-list" id="rakay-session-list">
      <div class="rakay-session-empty">Loading sessions…</div>
    </div>
  </aside>

  <!-- Main chat area -->
  <main class="rakay-main">

    <!-- Header -->
    <div class="rakay-header">
      <div class="rakay-header-icon"><i class="fas fa-robot"></i></div>
      <div class="rakay-header-info">
        <div class="rakay-header-title" id="rakay-current-title">RAKAY — AI Security Analyst</div>
        <div class="rakay-header-sub">Conversational threat intelligence • Detection engineering</div>
      </div>
      <div class="rakay-status-dot" id="rakay-status-dot" title="Backend status"></div>
    </div>

    <!-- Messages -->
    <div id="rakay-messages">
      ${_renderWelcome()}
    </div>

    <!-- Input -->
    <div class="rakay-input-area">
      <div class="rakay-input-wrap">
        <textarea
          id="rakay-input"
          placeholder="Ask RAKAY anything — Sigma rules, IOC enrichment, CVEs, MITRE ATT&CK…"
          rows="1"
          oninput="(function(el){el.style.height='auto';el.style.height=Math.min(el.scrollHeight,200)+'px';})(this)"
          onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();window._rakaySubmit();}"
        ></textarea>
        <button id="rakay-send" onclick="window._rakaySubmit()" title="Send (Enter)">
          <i class="fas fa-paper-plane"></i>
        </button>
      </div>
      <div class="rakay-input-hint">
        <i class="fas fa-keyboard"></i>
        Press <kbd style="background:#161b22;border:1px solid #30363d;padding:1px 5px;border-radius:3px;font-size:10px">Enter</kbd>
        to send · <kbd style="background:#161b22;border:1px solid #30363d;padding:1px 5px;border-radius:3px;font-size:10px">Shift+Enter</kbd>
        for new line
      </div>
    </div>

  </main>
</div>`;
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  MAIN RENDER & LIFECYCLE
  // ══════════════════════════════════════════════════════════════════════════

  async function renderRAKAY() {
    const page = document.getElementById('page-rakay');
    if (!page) {
      console.warn('[RAKAY] #page-rakay element not found');
      return;
    }

    // Inject styles
    _injectCSS();

    // Render shell
    page.innerHTML = _buildHTML();
    _rendered = true;

    // Initialise state
    await _loadSessions();

    if (!RAKAY.sessions.length) {
      // Create first session
      await _startNewChat();
    } else {
      // Select the most-recent session
      RAKAY.sessionId = RAKAY.sessions[0].id;
      _renderSidebar();
      _updateHeader();
      await _loadHistory(RAKAY.sessionId);
      _renderMessages();
      _scrollToBottom(false);
    }

    _focusInput();

    // Update status dot
    _updateStatus();

    // Periodically update relative timestamps
    RAKAY.pollingTimer = setInterval(() => {
      _renderSidebar();
      _updateStatus();
    }, 30_000);

    console.log('[RAKAY] Module v1.0 loaded. Session:', RAKAY.sessionId);
  }

  function stopRAKAY() {
    if (RAKAY.pollingTimer) {
      clearInterval(RAKAY.pollingTimer);
      RAKAY.pollingTimer = null;
    }
    _rendered = false;
    console.log('[RAKAY] Module stopped.');
  }

  function _updateStatus() {
    const dot = document.getElementById('rakay-status-dot');
    if (!dot) return;
    if (RAKAY.backendOnline === false) {
      dot.classList.add('offline');
      dot.title = 'Backend offline — using local cache';
    } else {
      dot.classList.remove('offline');
      dot.title = 'Backend connected';
    }
  }

  // ── Expose to platform ────────────────────────────────────────────────────
  window.renderRAKAY = renderRAKAY;
  window.stopRAKAY   = stopRAKAY;

  console.log('[RAKAY] Module v1.0 registered ✅');

})();
