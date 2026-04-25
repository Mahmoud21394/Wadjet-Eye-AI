/**
 * ACE v6 Node.js Test Harness
 * Stubs browser globals so raykan.js CSDE engine runs in Node.js
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const vm   = require('vm');

// ── Browser stubs ─────────────────────────────────────────────────────────────
const windowStub = {
  BACKEND_URL         : () => 'http://localhost',
  UnifiedTokenStore   : { getToken: () => '' },
  TokenStore          : { getToken: () => '' },
  CSDE                : null,
  RAYKAN_UI           : null,
  WebSocket           : class { constructor(){} },
  fetch               : async () => ({ ok: true, json: async () => ({}) }),
  console             : console,
};

const documentStub = {
  getElementById   : () => ({ textContent:'', innerHTML:'', classList:{ toggle:()=>{}, add:()=>{}, remove:()=>{} }, querySelectorAll:()=>[], addEventListener:()=>{} }),
  querySelectorAll : () => [],
  querySelector    : () => null,
  createElement    : () => ({ style:{}, classList:{ add:()=>{}, remove:()=>{} }, addEventListener:()=>{}, setAttribute:()=>{} }),
};

// ── Load and execute raykan.js in a sandboxed VM context ──────────────────────
function loadCSDE() {
  const src = fs.readFileSync(path.join(__dirname, 'js/raykan.js'), 'utf8');

  const ctx = vm.createContext({
    window    : windowStub,
    document  : documentStub,
    console,
    setTimeout  : (fn, ms) => { try { fn(); } catch {} },
    clearTimeout: () => {},
    setInterval : () => 0,
    clearInterval: () => {},
    performance : { now: () => Date.now() },
    WebSocket   : class { constructor(){} },
    fetch       : async () => ({ ok: true, json: async () => ({}) }),
    URL         : URL,
    Date,
    Math,
    JSON,
    Array,
    Object,
    Map,
    Set,
    Promise,
    RegExp,
    Error,
    parseInt,
    parseFloat,
    isNaN,
    isFinite,
    encodeURIComponent,
    decodeURIComponent,
    String,
    Number,
    Boolean,
    Symbol,
    Infinity,
    NaN,
    undefined,
    module     : {},
  });

  try {
    vm.runInContext(src, ctx, { filename: 'raykan.js' });
  } catch (e) {
    // UI/DOM errors during module-level execution are expected — ignore
    // as long as CSDE was assigned before the error
    if (!ctx.window.CSDE) {
      throw new Error(`Failed to load CSDE: ${e.message}`);
    }
  }

  const csde = ctx.window.CSDE;
  if (!csde || typeof csde.analyzeEvents !== 'function') {
    throw new Error('CSDE.analyzeEvents not found after module execution');
  }
  return csde;
}

module.exports = { loadCSDE };
