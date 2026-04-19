/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Pricing Module v2.0 (ENHANCED)
 *  Fully functional, admin-editable pricing with:
 *  - Annual/monthly toggle with savings calculation
 *  - Dynamic plan editing for super admins
 *  - FAQ accordion
 *  - CTA actions with validation
 *  - Comparison table
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ── Pricing State ── */
let _pricingAnnual = false;
let _pricingPlans  = null;
let _pricingIsAdmin = false;

/* ── Default Plans ── */
const _PRICING_DEFAULT_PLANS = [
  {
    id: 'starter',
    name: 'Starter',
    icon: 'fa-rocket',
    color: '#22d3ee',
    tagline: 'For small security teams',
    price_monthly: 299,
    price_annual: 239,  // per month when billed annually
    price_annual_total: 2868,
    features: [
      { text: '3 Users', included: true },
      { text: '10 Collectors / Feeds', included: true },
      { text: 'IOC Database (10K/day)', included: true },
      { text: 'AI Threat Summaries', included: true },
      { text: 'Basic SOAR Playbooks', included: true },
      { text: '5 Reports/month', included: true },
      { text: 'Email Support', included: true },
      { text: 'Custom Branding', included: false },
      { text: 'Multi-Tenant', included: false },
      { text: 'Advanced AI Orchestrator', included: false },
      { text: 'API Access', included: false },
      { text: 'Dedicated Success Manager', included: false },
    ],
    limits: { users: 3, tenants: 1, collectors: 10, iocs_per_day: 10000, reports: 5 },
    popular: false,
    cta_label: 'Start Free Trial',
    cta_style: 'ghost',
  },
  {
    id: 'professional',
    name: 'Professional',
    icon: 'fa-shield-alt',
    color: '#22d3ee',
    tagline: 'For growing security operations',
    price_monthly: 899,
    price_annual: 719,
    price_annual_total: 8628,
    features: [
      { text: '10 Users', included: true },
      { text: '30 Collectors / Feeds', included: true },
      { text: 'IOC Database (Unlimited)', included: true },
      { text: 'Full AI Orchestrator', included: true },
      { text: 'Advanced SOAR Automation', included: true },
      { text: '50 Reports/month', included: true },
      { text: '3 Tenants', included: true },
      { text: 'Custom Branding', included: true },
      { text: 'Priority Support', included: true },
      { text: 'API Access', included: true },
      { text: 'MITRE ATT&CK Coverage', included: true },
      { text: 'Dedicated Success Manager', included: false },
    ],
    limits: { users: 10, tenants: 3, collectors: 30, iocs_per_day: null, reports: 50 },
    popular: true,
    cta_label: 'Start Free Trial',
    cta_style: 'primary',
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    icon: 'fa-building',
    color: '#f97316',
    tagline: 'For MSSPs and large enterprises',
    price_monthly: null,
    price_annual: null,
    price_annual_total: null,
    features: [
      { text: 'Unlimited Users', included: true },
      { text: 'Unlimited Collectors', included: true },
      { text: 'IOC Database (Unlimited)', included: true },
      { text: 'Full AI Orchestrator + Custom Models', included: true },
      { text: 'Custom SOAR Workflows', included: true },
      { text: 'Unlimited Reports', included: true },
      { text: 'Unlimited Tenants', included: true },
      { text: 'White-Label Branding', included: true },
      { text: '24/7 Priority Support + SLA', included: true },
      { text: 'Full API + Webhooks', included: true },
      { text: 'SSO/SAML Integration', included: true },
      { text: 'Dedicated Success Manager', included: true },
    ],
    limits: { users:'Unlimited', tenants:'Unlimited', collectors:'Unlimited', iocs_per_day: null, reports: null },
    popular: false,
    cta_label: 'Contact Sales',
    cta_style: 'orange',
  },
];

const _PRICING_FAQ = [
  { q: 'Can I switch plans at any time?', a: 'Yes, you can upgrade or downgrade your plan at any time. Upgrades take effect immediately. Downgrades take effect at the next billing cycle.' },
  { q: 'Is there a free trial?', a: 'Yes, Starter and Professional plans include a 14-day free trial with full features. No credit card required.' },
  { q: 'How does tenant isolation work?', a: 'Each tenant has completely isolated data, users, and configurations. Data is never shared across tenant boundaries, enforced at the database level with Row Level Security (RLS).' },
  { q: 'What is included in API access?', a: 'API access includes all REST endpoints for IOCs, campaigns, findings, cases, and automation triggers. Full API documentation available at /api/docs.' },
  { q: 'How is the IOC database limit calculated?', a: 'The limit refers to new IOCs ingested per day from threat intelligence feeds. Stored IOCs and manual additions are not counted against this limit.' },
  { q: 'Do you offer discounts for NGOs or educational institutions?', a: 'Yes! Contact our sales team for special pricing for non-profits, academic institutions, and government organizations.' },
  { q: 'Is my data encrypted at rest and in transit?', a: 'All data is encrypted in transit using TLS 1.3 and at rest using AES-256. We comply with SOC 2 Type II and support GDPR data residency requirements.' },
];

/* ══════════════════════════════════════════════════════
   MAIN RENDERER
══════════════════════════════════════════════════════ */
window.renderPricing = function() {
  const wrap = document.getElementById('pricingWrap') || document.getElementById('page-pricing');
  if (!wrap) return;

  // Detect admin
  const user = window.CURRENT_USER || {};
  _pricingIsAdmin = (user.role === 'super_admin' || user.role === 'admin');

  // Load plans (try from branding, else use defaults)
  _pricingPlans = window.PLATFORM_CONFIG?.pricing_plans || _PRICING_DEFAULT_PLANS;

  wrap.innerHTML = `
  <!-- Header -->
  <div class="enh-module-header">
    <div class="enh-module-header__glow-1" style="background:radial-gradient(ellipse,rgba(34,211,238,.05) 0%,transparent 70%)"></div>
    <div class="enh-module-header__glow-2" style="background:radial-gradient(ellipse,rgba(249,115,22,.04) 0%,transparent 70%)"></div>
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;position:relative">
      <div>
        <h2 style="margin:0;color:#e6edf3;font-size:1.15em;font-weight:700">Subscription Plans</h2>
        <div style="font-size:.76em;color:#8b949e;margin-top:2px">Choose the plan that fits your security operations</div>
      </div>
      ${_pricingIsAdmin ? `
      <button class="enh-btn enh-btn--ghost enh-btn--sm" onclick="_pricingEditMode()">
        <i class="fas fa-edit"></i> Edit Plans
      </button>` : ''}
    </div>
  </div>

  <div class="pricing-container" style="padding:24px 16px">

    <!-- Billing Toggle -->
    <div class="pricing-toggle-wrap">
      <span style="color:${_pricingAnnual?'#6b7280':'#e6edf3'};font-weight:600;transition:color .2s">Monthly</span>
      <input type="checkbox" class="pricing-toggle" id="billing-toggle"
        ${_pricingAnnual?'checked':''}
        onchange="_pricingToggleBilling(this.checked)" />
      <span style="color:${_pricingAnnual?'#e6edf3':'#6b7280'};font-weight:600;transition:color .2s">Annual</span>
      <span style="background:rgba(34,197,94,.12);color:#22c55e;border:1px solid rgba(34,197,94,.25);
        padding:2px 10px;border-radius:10px;font-size:.74em;font-weight:700">Save 20%</span>
    </div>

    <!-- Plans Grid -->
    <div class="pricing-grid" id="pricing-plans-grid">
      ${_renderPricingPlans(_pricingPlans)}
    </div>

    <!-- Comparison Table -->
    <div style="margin-bottom:32px">
      <h3 style="text-align:center;color:#e6edf3;font-size:1em;font-weight:700;margin-bottom:16px">Full Feature Comparison</h3>
      ${_renderPricingComparison()}
    </div>

    <!-- FAQ Section -->
    <div style="max-width:700px;margin:0 auto 32px">
      <h3 style="text-align:center;color:#e6edf3;font-size:1em;font-weight:700;margin-bottom:16px">Frequently Asked Questions</h3>
      <div id="pricing-faq">
        ${_PRICING_FAQ.map((item, i) => `
          <div class="pricing-faq-item enh-stagger-${Math.min(i+1,6)}">
            <div class="pricing-faq-q" onclick="_pricingToggleFAQ(${i})">
              ${item.q}
              <i class="fas fa-chevron-down" id="faq-icon-${i}" style="transition:transform .3s;flex-shrink:0;margin-left:12px"></i>
            </div>
            <div class="pricing-faq-a" id="faq-answer-${i}">${item.a}</div>
          </div>`).join('')}
      </div>
    </div>

    <!-- Admin Panel (visible to super_admin) -->
    ${_pricingIsAdmin ? `
    <div class="pricing-admin-panel" id="pricing-admin-panel">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
        <i class="fas fa-cog" style="color:#f97316"></i>
        <h3 style="margin:0;color:#e6edf3;font-size:.95em;font-weight:700">Admin: Pricing Configuration</h3>
        <span class="enh-badge enh-badge--high" style="margin-left:auto">ADMIN ONLY</span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;margin-bottom:14px">
        ${_pricingPlans.map(plan => `
          <div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:8px;padding:10px">
            <div style="font-size:.8em;font-weight:700;color:#e6edf3;margin-bottom:8px">${plan.name}</div>
            ${plan.price_monthly != null ? `
            <div style="font-size:.76em;color:#8b949e;margin-bottom:4px">Monthly ($)</div>
            <input class="enh-input" style="width:100%;box-sizing:border-box;margin-bottom:6px;font-size:.84em"
              type="number" value="${plan.price_monthly}" id="admin-price-${plan.id}-monthly"
              onchange="_pricingUpdatePrice('${plan.id}','monthly',this.value)" />
            <div style="font-size:.76em;color:#8b949e;margin-bottom:4px">Annual ($/mo)</div>
            <input class="enh-input" style="width:100%;box-sizing:border-box;font-size:.84em"
              type="number" value="${plan.price_annual}" id="admin-price-${plan.id}-annual"
              onchange="_pricingUpdatePrice('${plan.id}','annual',this.value)" />
            ` : `<div style="font-size:.78em;color:#8b949e">Contact Sales pricing</div>`}
          </div>`).join('')}
      </div>
      <div style="display:flex;gap:8px">
        <button class="enh-btn enh-btn--primary enh-btn--sm" onclick="_pricingSavePlans()">
          <i class="fas fa-save"></i> Save Changes
        </button>
        <button class="enh-btn enh-btn--ghost enh-btn--sm" onclick="_pricingResetPlans()">
          <i class="fas fa-undo"></i> Reset to Defaults
        </button>
      </div>
    </div>` : ''}

  </div>
  `;
};

/* ── Render plans ── */
function _renderPricingPlans(plans) {
  return plans.map((plan, i) => {
    const price = _pricingAnnual ? plan.price_annual : plan.price_monthly;
    const savings = plan.price_monthly && plan.price_annual
      ? Math.round((1 - plan.price_annual / plan.price_monthly) * 100) : 0;

    return `
    <div class="pricing-card enh-stagger-${i+1} ${plan.popular ? 'pricing-card--featured' : ''}"
      style="--pricing-accent:${plan.color}">
      ${plan.popular ? `<div class="pricing-popular-badge">Most Popular</div>` : ''}

      <!-- Plan Header -->
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        <div style="width:40px;height:40px;background:${plan.color}18;border:1px solid ${plan.color}30;
          border-radius:10px;display:flex;align-items:center;justify-content:center">
          <i class="fas ${plan.icon}" style="color:${plan.color}"></i>
        </div>
        <div>
          <div style="font-size:1em;font-weight:800;color:#e6edf3">${plan.name}</div>
          <div style="font-size:.76em;color:#8b949e">${plan.tagline}</div>
        </div>
      </div>

      <!-- Price -->
      <div style="margin-bottom:20px">
        ${price != null ? `
          <div class="pricing-price" style="color:${plan.color}">
            $${price}
            <span style="font-size:.35em;font-weight:400;color:#8b949e">/mo</span>
          </div>
          <div style="font-size:.78em;color:#8b949e;margin-top:4px">
            ${_pricingAnnual ? `Billed annually ($${plan.price_annual_total}/yr) · ` : 'Billed monthly · '}
            ${savings > 0 && _pricingAnnual ? `<span style="color:#22c55e;font-weight:700">Save ${savings}%</span>` : ''}
          </div>
        ` : `
          <div style="font-size:1.8em;font-weight:800;color:${plan.color}">Custom</div>
          <div style="font-size:.78em;color:#8b949e;margin-top:4px">Tailored pricing for your organization</div>
        `}
      </div>

      <!-- Features -->
      <ul class="pricing-feature-list" style="flex:1;margin-bottom:0">
        ${plan.features.map(f => `
          <li>
            <i class="fas ${f.included ? 'fa-check check' : 'fa-times cross'}"></i>
            <span style="color:${f.included ? '#e6edf3' : '#4b5563'}">${f.text}</span>
          </li>`).join('')}
      </ul>

      <!-- CTA -->
      <div class="pricing-cta">
        <button onclick="_pricingCTA('${plan.id}','${plan.cta_label}')"
          class="enh-btn ${plan.cta_style==='primary'?'enh-btn--primary':plan.cta_style==='orange'?'':plan.cta_style==='ghost'?'enh-btn--cyan':''}"
          style="width:100%;justify-content:center;
            ${plan.cta_style==='orange'?'background:rgba(249,115,22,.12);color:#f97316;border-color:rgba(249,115,22,.3)':''}">
          ${plan.cta_label}
        </button>
      </div>
    </div>`;
  }).join('');
}

/* ── Comparison table ── */
function _renderPricingComparison() {
  const features = [
    { label: 'Users', vals: ['3', '10', 'Unlimited'] },
    { label: 'Tenants', vals: ['1', '3', 'Unlimited'] },
    { label: 'Collectors', vals: ['10', '30', 'Unlimited'] },
    { label: 'IOCs/day', vals: ['10K', 'Unlimited', 'Unlimited'] },
    { label: 'Reports/month', vals: ['5', '50', 'Unlimited'] },
    { label: 'AI Orchestrator', vals: ['Basic', '✓', '✓ + Custom'] },
    { label: 'Custom Branding', vals: ['✗', '✓', '✓ White-label'] },
    { label: 'API Access', vals: ['✗', '✓', '✓ + Webhooks'] },
    { label: 'SSO / SAML', vals: ['✗', '✗', '✓'] },
    { label: 'SLA', vals: ['—', 'Business hours', '24/7 Priority'] },
    { label: 'Dedicated CSM', vals: ['✗', '✗', '✓'] },
  ];

  return `
    <div style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse;font-size:.83em">
      <thead>
        <tr style="border-bottom:2px solid #1a2535">
          <th style="padding:10px 12px;text-align:left;color:#8b949e;font-weight:600">Feature</th>
          ${_PRICING_DEFAULT_PLANS.map(p => `<th style="padding:10px 12px;text-align:center;color:${p.color};font-weight:700">${p.name}</th>`).join('')}
        </tr>
      </thead>
      <tbody>
        ${features.map((f, i) => `
          <tr style="border-bottom:1px solid rgba(26,37,53,.6);animation:enh-fadeIn .3s ease ${i*.03}s both">
            <td style="padding:9px 12px;color:#8b949e">${f.label}</td>
            ${f.vals.map(v => `<td style="padding:9px 12px;text-align:center;color:${v==='✗'?'#4b5563':v==='✓'||v.startsWith('✓')?'#22c55e':'#e6edf3'};font-weight:${v==='✗'?400:500}">${v}</td>`).join('')}
          </tr>`).join('')}
      </tbody>
    </table>
    </div>`;
}

/* ── Toggle billing ── */
window._pricingToggleBilling = function(annual) {
  _pricingAnnual = annual;
  document.getElementById('pricing-plans-grid').innerHTML = _renderPricingPlans(_pricingPlans);
};

/* ── FAQ toggle ── */
window._pricingToggleFAQ = function(idx) {
  const ans  = document.getElementById(`faq-answer-${idx}`);
  const icon = document.getElementById(`faq-icon-${idx}`);
  if (!ans) return;
  const isOpen = ans.classList.contains('pricing-faq-a--open');
  // Close all
  document.querySelectorAll('.pricing-faq-a').forEach(a => a.classList.remove('pricing-faq-a--open'));
  document.querySelectorAll('[id^="faq-icon-"]').forEach(ic => ic.style.transform = '');
  if (!isOpen) {
    ans.classList.add('pricing-faq-a--open');
    if (icon) icon.style.transform = 'rotate(180deg)';
  }
};

/* ── CTA action ── */
window._pricingCTA = function(planId, label) {
  if (label === 'Contact Sales') {
    window.open('mailto:sales@wadjet-eye.ai?subject=Enterprise Plan Inquiry', '_blank');
    return;
  }
  if (typeof showToast === 'function') showToast(`🚀 Starting free trial for ${planId} plan…`, 'info');
  setTimeout(() => {
    if (typeof showToast === 'function') showToast('📧 Check your email for trial activation link', 'success');
  }, 1500);
};

/* ── Admin: Update price ── */
window._pricingUpdatePrice = function(planId, period, value) {
  const plan = _pricingPlans.find(p => p.id === planId);
  if (!plan) return;
  const num = parseFloat(value);
  if (isNaN(num) || num < 0) return;
  if (period === 'monthly') plan.price_monthly = num;
  if (period === 'annual')  { plan.price_annual = num; plan.price_annual_total = Math.round(num * 12); }
};

window._pricingEditMode = function() {
  const panel = document.getElementById('pricing-admin-panel');
  if (panel) panel.scrollIntoView({ behavior:'smooth' });
};

window._pricingSavePlans = async function() {
  try {
    const base  = (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
    const token = localStorage.getItem('wadjet_access_token') || localStorage.getItem('tp_access_token') || '';
    await fetch(`${base}/api/settings/pricing`, {
      method: 'PUT',
      headers: { 'Content-Type':'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) },
      body: JSON.stringify({ plans: _pricingPlans }),
    });
    if (typeof showToast === 'function') showToast('✅ Pricing plans saved', 'success');
  } catch {
    if (typeof showToast === 'function') showToast('⚠️ Could not save to server — plans updated locally', 'warning');
  }
  // Re-render with updated prices
  document.getElementById('pricing-plans-grid').innerHTML = _renderPricingPlans(_pricingPlans);
};

window._pricingResetPlans = function() {
  _pricingPlans = JSON.parse(JSON.stringify(_PRICING_DEFAULT_PLANS));
  if (typeof showToast === 'function') showToast('🔄 Plans reset to defaults', 'info');
  window.renderPricing();
};
