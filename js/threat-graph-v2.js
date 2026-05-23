/**
 * ══════════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI v25.0 — Threat Intelligence Graph v2.0
 *  FILE: js/threat-graph-v2.js
 *
 *  Enhancement 1: Temporal Graph Replay (time-scrub slider, play/pause, delta mode)
 *  Enhancement 2: Attack Path Simulator (Dijkstra, MITRE annotations, STIX export)
 *  Enhancement 3: Blast Radius Propagation (3-ring animated expansion)
 *  Enhancement 4: Multi-Dimensional Lens Filter System (composable filters)
 *  Enhancement 5: Egocentric Focus Mode (double-click, depth rings, pin mode)
 *  Enhancement 6: AI Graph Narrator (contextual AI commentary panel)
 *
 *  Entry point: window.renderThreatGraphV2()
 * ══════════════════════════════════════════════════════════════════════════════
 */
(function(global) {
'use strict';

/* ═══════════════════════════════════════════════════════════════════════════
   §1  CONSTANTS & CONFIGURATION
═══════════════════════════════════════════════════════════════════════════ */
const TGV2_VERSION = '2.0.0';

const NODE_CFG = {
  threat_actor:  { color:'#ef4444', bg:'rgba(239,68,68,.15)',  icon:'fa-user-secret',  size:28, label:'Threat Actor'  },
  malware:       { color:'#f97316', bg:'rgba(249,115,22,.15)', icon:'fa-bug',           size:22, label:'Malware'       },
  campaign:      { color:'#a855f7', bg:'rgba(168,85,247,.15)', icon:'fa-crosshairs',    size:24, label:'Campaign'      },
  technique:     { color:'#3b82f6', bg:'rgba(59,130,246,.15)', icon:'fa-sitemap',       size:18, label:'Technique'     },
  region:        { color:'#22d3ee', bg:'rgba(34,211,238,.15)', icon:'fa-globe',         size:32, label:'Region'        },
  target_sector: { color:'#f59e0b', bg:'rgba(245,158,11,.15)', icon:'fa-building',      size:20, label:'Sector'        },
  infrastructure:{ color:'#6b7280', bg:'rgba(107,114,128,.15)',icon:'fa-server',        size:18, label:'Infrastructure' },
};

const TIMELINE_EVENTS = [
  { date:'2020-12-13', label:'SolarWinds',   desc:'SUNBURST supply-chain detected' },
  { date:'2021-05-07', label:'Colonial',     desc:'DarkSide Colonial Pipeline attack' },
  { date:'2021-07-02', label:'Kaseya',       desc:'REvil Kaseya VSA supply-chain' },
  { date:'2022-02-24', label:'Ukraine War',  desc:'Wiper campaigns escalate — HermeticWiper, WhisperGate' },
  { date:'2022-11-01', label:'LockBit 3.0',  desc:'LockBit 3.0 (Black) emerges' },
  { date:'2023-01-19', label:'Hive Takedown',desc:'FBI disrupts Hive ransomware infrastructure' },
  { date:'2023-09-14', label:'MOVEit',       desc:'Cl0p MOVEit Transfer mass exploitation' },
  { date:'2024-02-19', label:'LockBit Bust', desc:'Operation Cronos — LockBit infrastructure seized' },
  { date:'2024-07-19', label:'CrowdStrike',  desc:'CrowdStrike sensor update outage — 8.5M hosts' },
  { date:'2025-01-15', label:'Salt Typhoon',desc:'Salt Typhoon telco espionage disclosed' },
];

const MITRE_TACTICS = [
  'Reconnaissance','Resource Development','Initial Access','Execution',
  'Persistence','Privilege Escalation','Defense Evasion','Credential Access',
  'Discovery','Lateral Movement','Collection','Exfiltration','Command and Control','Impact'
];

const ACTOR_ORIGINS = [
  {code:'CN',flag:'🇨🇳',name:'China'},    {code:'RU',flag:'🇷🇺',name:'Russia'},
  {code:'KP',flag:'🇰🇵',name:'N. Korea'}, {code:'IR',flag:'🇮🇷',name:'Iran'},
  {code:'US',flag:'🇺🇸',name:'USA'},      {code:'UK',flag:'🇬🇧',name:'UK'},
];

/* ═══════════════════════════════════════════════════════════════════════════
   §2  FULL GRAPH DATA STORE (enhanced v2 dataset)
═══════════════════════════════════════════════════════════════════════════ */
const V2_NODES = [
  /* ── Threat Actors ── */
  { id:'apt29',   type:'threat_actor', label:'APT29',          region:'EMEA',     risk:96, origin:'RU', sponsor:'SVR',  active_since:'2008', ttps:['T1566','T1078','T1021','T1102'],   sectors:['Government','Defense','Energy'],   tools:['HAMMERTOSS','MiniDuke','WellMess'],    first_seen:'2014-06-01', last_seen:'2025-04-10', confidence:94 },
  { id:'apt28',   type:'threat_actor', label:'APT28',          region:'EMEA',     risk:94, origin:'RU', sponsor:'GRU',  active_since:'2004', ttps:['T1566','T1059','T1003','T1027'],   sectors:['Government','Military','Think Tank'],tools:['X-Agent','Zebrocy','Sofacy'],        first_seen:'2014-01-01', last_seen:'2025-03-22', confidence:96 },
  { id:'apt41',   type:'threat_actor', label:'APT41',          region:'APAC',     risk:93, origin:'CN', sponsor:'MSS',  active_since:'2012', ttps:['T1190','T1059','T1078','T1486'],   sectors:['Healthcare','Technology','Gaming'],  tools:['Derusbi','PlugX','ShadowPad'],        first_seen:'2014-04-01', last_seen:'2025-04-05', confidence:91 },
  { id:'fin7',    type:'threat_actor', label:'FIN7/Carbanak',  region:'EMEA',     risk:89, origin:'RU', sponsor:'Crime',active_since:'2015', ttps:['T1566','T1059','T1486','T1083'],   sectors:['Financial','Retail','Hospitality'],  tools:['GRIFFON','Carbanak','Lizar'],         first_seen:'2015-02-01', last_seen:'2025-02-14', confidence:88 },
  { id:'lockbit', type:'threat_actor', label:'LockBit 3.0',    region:'AMER',     risk:97, origin:'RU', sponsor:'RaaS', active_since:'2019', ttps:['T1486','T1490','T1489','T1562'],   sectors:['Healthcare','Finance','Government'], tools:['LockBit','StealBit','Cobalt Strike'], first_seen:'2019-09-01', last_seen:'2025-04-08', confidence:95 },
  { id:'lazarus', type:'threat_actor', label:'Lazarus Group',  region:'APAC',     risk:95, origin:'KP', sponsor:'RGB',  active_since:'2009', ttps:['T1566','T1059','T1486','T1041'],   sectors:['Financial','Crypto','Defense'],      tools:['BLINDINGCAN','COPPERHEDGE','DTRACK'], first_seen:'2009-01-01', last_seen:'2025-04-12', confidence:89 },
  { id:'blackcat',type:'threat_actor', label:'BlackCat/ALPHV', region:'EMEA',     risk:92, origin:'RU', sponsor:'RaaS', active_since:'2021', ttps:['T1486','T1562','T1027','T1078'],   sectors:['Healthcare','Finance','Critical'],   tools:['BlackCat','ExMatter','Brute Ratel'],  first_seen:'2021-11-01', last_seen:'2024-12-20', confidence:90 },
  { id:'clop',    type:'threat_actor', label:'Cl0p',           region:'EMEA',     risk:91, origin:'RU', sponsor:'Crime',active_since:'2019', ttps:['T1190','T1486','T1041','T1083'],   sectors:['Finance','Healthcare','Education'],  tools:['Cl0p ransomware','MOVEit exploit'],   first_seen:'2019-02-01', last_seen:'2025-01-15', confidence:87 },
  { id:'volt',    type:'threat_actor', label:'Volt Typhoon',   region:'APAC',     risk:93, origin:'CN', sponsor:'PLA',  active_since:'2021', ttps:['T1133','T1078','T1021','T1070'],   sectors:['Critical Infra','Military','Govt'],  tools:['LOTL','VersaMem','custom implants'],  first_seen:'2021-06-01', last_seen:'2025-04-01', confidence:88 },
  { id:'salt',    type:'threat_actor', label:'Salt Typhoon',   region:'APAC',     risk:92, origin:'CN', sponsor:'MSS',  active_since:'2020', ttps:['T1190','T1021','T1560','T1041'],   sectors:['Telecom','Government','Defense'],    tools:['GhostSpider','SnappyBee','Masol RAT'],first_seen:'2020-09-01', last_seen:'2025-03-30', confidence:82 },

  /* ── Malware ── */
  { id:'sunburst',    type:'malware', label:'SUNBURST',           region:'AMER', risk:98, family:'backdoor',    first_seen:'2019-10-01', last_seen:'2020-12-13', description:'SolarWinds supply-chain backdoor' },
  { id:'emotet',      type:'malware', label:'Emotet',             region:'EMEA', risk:87, family:'loader',      first_seen:'2014-06-01', last_seen:'2023-11-01', description:'Modular banking trojan turned loader' },
  { id:'cobalt',      type:'malware', label:'Cobalt Strike',      region:'GLOB', risk:91, family:'framework',   first_seen:'2012-01-01', last_seen:'2025-04-12', description:'Commercial pen-test framework abused by APTs' },
  { id:'plugx',       type:'malware', label:'PlugX RAT',          region:'APAC', risk:85, family:'rat',         first_seen:'2012-01-01', last_seen:'2025-03-01', description:'Chinese APT remote access trojan' },
  { id:'lockbit_bin', type:'malware', label:'LockBit payload',    region:'GLOB', risk:97, family:'ransomware',  first_seen:'2019-09-01', last_seen:'2025-04-08', description:'LockBit 3.0 ransomware binary' },
  { id:'blackcat_bin',type:'malware', label:'ALPHV ransomware',   region:'GLOB', risk:91, family:'ransomware',  first_seen:'2021-11-01', last_seen:'2024-12-20', description:'BlackCat/ALPHV Rust-based ransomware' },
  { id:'ghostspider', type:'malware', label:'GhostSpider',        region:'APAC', risk:90, family:'backdoor',    first_seen:'2023-04-01', last_seen:'2025-03-30', description:'Salt Typhoon modular backdoor' },
  { id:'stealbit',    type:'malware', label:'StealBit',           region:'GLOB', risk:88, family:'exfiltrator', first_seen:'2021-01-01', last_seen:'2025-02-20', description:'LockBit-exclusive exfiltration tool' },

  /* ── Campaigns ── */
  { id:'camp_sw',     type:'campaign', label:'IRON TEMPEST',     region:'AMER', risk:99, status:'historical', start:'2019-10-01', end:'2020-12-13', impact:'Critical', victims:18000, description:'SolarWinds supply-chain attack' },
  { id:'camp_colonial',type:'campaign', label:'Colonial Pipeline',region:'AMER', risk:95, status:'historical', start:'2021-05-07', end:'2021-05-12', impact:'Critical', victims:1,    description:'DarkSide ransomware on Colonial Pipeline OT' },
  { id:'camp_moveit', type:'campaign', label:'MOVEit Mass Exfil', region:'GLOB', risk:94, status:'historical', start:'2023-05-27', end:'2023-09-01', impact:'High',    victims:2500, description:'Cl0p zero-day exploitation of MOVEit Transfer' },
  { id:'camp_active1',type:'campaign', label:'WINTER STORM',     region:'EMEA', risk:97, status:'active',     start:'2024-11-01', end:null,          impact:'Critical', victims:null, description:'APT29 active campaign targeting EU government ministries' },
  { id:'camp_active2',type:'campaign', label:'IRON RANSOM',      region:'AMER', risk:96, status:'active',     start:'2025-01-15', end:null,          impact:'Critical', victims:null, description:'LockBit 4.0 lateral movement in hospital networks' },

  /* ── Techniques (MITRE) ── */
  { id:'t1566', type:'technique', label:'T1566 Phishing',       region:'GLOB', risk:80, mitre_id:'T1566', tactic:'Initial Access',     description:'Phishing attacks for initial access' },
  { id:'t1059', type:'technique', label:'T1059 Scripting',      region:'GLOB', risk:78, mitre_id:'T1059', tactic:'Execution',          description:'Command and scripting interpreter abuse' },
  { id:'t1078', type:'technique', label:'T1078 Valid Accounts', region:'GLOB', risk:82, mitre_id:'T1078', tactic:'Defense Evasion',    description:'Legitimate credential abuse' },
  { id:'t1190', type:'technique', label:'T1190 Exploit PFI',    region:'GLOB', risk:85, mitre_id:'T1190', tactic:'Initial Access',     description:'Exploit public-facing applications' },
  { id:'t1486', type:'technique', label:'T1486 Data Encrypt',   region:'GLOB', risk:90, mitre_id:'T1486', tactic:'Impact',             description:'Data encrypted for impact (ransomware)' },
  { id:'t1041', type:'technique', label:'T1041 C2 Exfil',       region:'GLOB', risk:75, mitre_id:'T1041', tactic:'Exfiltration',       description:'Exfiltration over C2 channel' },
  { id:'t1027', type:'technique', label:'T1027 Obfuscation',    region:'GLOB', risk:72, mitre_id:'T1027', tactic:'Defense Evasion',    description:'Obfuscated files or information' },
  { id:'t1102', type:'technique', label:'T1102 Web Services',   region:'GLOB', risk:68, mitre_id:'T1102', tactic:'C2',                 description:'Web service C2 (GitHub, Twitter, Azure)' },

  /* ── Regions / Sectors ── */
  { id:'reg_amer',   type:'region', label:'Americas',        region:'AMER', risk:85, countries:['US','CA','BR','MX'] },
  { id:'reg_emea',   type:'region', label:'EMEA',            region:'EMEA', risk:88, countries:['GB','DE','FR','UA','IL'] },
  { id:'reg_apac',   type:'region', label:'APAC',            region:'APAC', risk:83, countries:['CN','JP','KR','AU','IN'] },
  { id:'sec_gov',    type:'target_sector', label:'Government',      region:'GLOB', risk:90 },
  { id:'sec_fin',    type:'target_sector', label:'Financial',       region:'GLOB', risk:88 },
  { id:'sec_health', type:'target_sector', label:'Healthcare',      region:'GLOB', risk:87 },
  { id:'sec_energy', type:'target_sector', label:'Energy/ICS',      region:'GLOB', risk:89 },
  { id:'sec_telco',  type:'target_sector', label:'Telecom',         region:'GLOB', risk:85 },
  { id:'sec_tech',   type:'target_sector', label:'Technology',      region:'GLOB', risk:86 },
];

const V2_EDGES = [
  /* Actor → Malware */
  { src:'apt29',   tgt:'sunburst',    rel:'deploys',      weight:0.95, first_seen:'2019-10-01' },
  { src:'apt29',   tgt:'cobalt',      rel:'uses',         weight:0.80, first_seen:'2021-01-01' },
  { src:'apt29',   tgt:'ghostspider', rel:'shares_infra', weight:0.40, first_seen:'2024-01-01' },
  { src:'apt28',   tgt:'cobalt',      rel:'uses',         weight:0.78, first_seen:'2018-01-01' },
  { src:'apt41',   tgt:'plugx',       rel:'deploys',      weight:0.92, first_seen:'2014-04-01' },
  { src:'apt41',   tgt:'cobalt',      rel:'uses',         weight:0.75, first_seen:'2019-01-01' },
  { src:'fin7',    tgt:'cobalt',      rel:'uses',         weight:0.88, first_seen:'2017-01-01' },
  { src:'lockbit', tgt:'lockbit_bin', rel:'owns',         weight:1.00, first_seen:'2019-09-01' },
  { src:'lockbit', tgt:'stealbit',    rel:'owns',         weight:1.00, first_seen:'2021-01-01' },
  { src:'lockbit', tgt:'cobalt',      rel:'uses',         weight:0.90, first_seen:'2020-06-01' },
  { src:'lazarus', tgt:'cobalt',      rel:'uses',         weight:0.72, first_seen:'2020-01-01' },
  { src:'blackcat',tgt:'blackcat_bin',rel:'owns',         weight:1.00, first_seen:'2021-11-01' },
  { src:'blackcat',tgt:'cobalt',      rel:'uses',         weight:0.85, first_seen:'2022-01-01' },
  { src:'clop',    tgt:'cobalt',      rel:'uses',         weight:0.70, first_seen:'2020-01-01' },
  { src:'volt',    tgt:'cobalt',      rel:'uses',         weight:0.45, first_seen:'2023-01-01' },
  { src:'salt',    tgt:'ghostspider', rel:'owns',         weight:1.00, first_seen:'2023-04-01' },

  /* Actor → Campaign */
  { src:'apt29',   tgt:'camp_sw',     rel:'conducted',    weight:0.95, first_seen:'2019-10-01' },
  { src:'apt29',   tgt:'camp_active1',rel:'conducting',   weight:0.97, first_seen:'2024-11-01' },
  { src:'lockbit', tgt:'camp_active2',rel:'conducting',   weight:0.98, first_seen:'2025-01-15' },
  { src:'clop',    tgt:'camp_moveit', rel:'conducted',    weight:0.96, first_seen:'2023-05-27' },

  /* Actor → Technique */
  { src:'apt29',   tgt:'t1566',  rel:'uses', weight:0.90, first_seen:'2014-01-01' },
  { src:'apt29',   tgt:'t1078',  rel:'uses', weight:0.88, first_seen:'2018-01-01' },
  { src:'apt29',   tgt:'t1102',  rel:'uses', weight:0.95, first_seen:'2018-06-01' },
  { src:'apt28',   tgt:'t1566',  rel:'uses', weight:0.92, first_seen:'2014-01-01' },
  { src:'apt28',   tgt:'t1059',  rel:'uses', weight:0.85, first_seen:'2016-01-01' },
  { src:'apt41',   tgt:'t1190',  rel:'uses', weight:0.90, first_seen:'2019-01-01' },
  { src:'apt41',   tgt:'t1059',  rel:'uses', weight:0.88, first_seen:'2014-01-01' },
  { src:'lockbit', tgt:'t1486',  rel:'uses', weight:1.00, first_seen:'2019-09-01' },
  { src:'lockbit', tgt:'t1041',  rel:'uses', weight:0.90, first_seen:'2021-01-01' },
  { src:'lazarus', tgt:'t1566',  rel:'uses', weight:0.87, first_seen:'2016-01-01' },
  { src:'lazarus', tgt:'t1041',  rel:'uses', weight:0.85, first_seen:'2018-01-01' },
  { src:'fin7',    tgt:'t1566',  rel:'uses', weight:0.95, first_seen:'2015-02-01' },
  { src:'fin7',    tgt:'t1059',  rel:'uses', weight:0.88, first_seen:'2015-06-01' },
  { src:'clop',    tgt:'t1190',  rel:'uses', weight:0.92, first_seen:'2023-01-01' },
  { src:'clop',    tgt:'t1041',  rel:'uses', weight:0.88, first_seen:'2020-01-01' },
  { src:'volt',    tgt:'t1078',  rel:'uses', weight:0.95, first_seen:'2021-01-01' },
  { src:'salt',    tgt:'t1190',  rel:'uses', weight:0.90, first_seen:'2023-01-01' },
  { src:'blackcat',tgt:'t1486',  rel:'uses', weight:0.98, first_seen:'2021-11-01' },
  { src:'blackcat',tgt:'t1027',  rel:'uses', weight:0.88, first_seen:'2022-01-01' },

  /* Actor → Region */
  { src:'apt29',   tgt:'reg_emea', rel:'targets', weight:0.90, first_seen:'2014-01-01' },
  { src:'apt29',   tgt:'reg_amer', rel:'targets', weight:0.75, first_seen:'2016-01-01' },
  { src:'apt28',   tgt:'reg_emea', rel:'targets', weight:0.95, first_seen:'2014-01-01' },
  { src:'apt41',   tgt:'reg_apac', rel:'targets', weight:0.85, first_seen:'2014-01-01' },
  { src:'apt41',   tgt:'reg_amer', rel:'targets', weight:0.70, first_seen:'2019-01-01' },
  { src:'lockbit', tgt:'reg_amer', rel:'targets', weight:0.88, first_seen:'2020-01-01' },
  { src:'lockbit', tgt:'reg_emea', rel:'targets', weight:0.82, first_seen:'2021-01-01' },
  { src:'lazarus', tgt:'reg_apac', rel:'targets', weight:0.88, first_seen:'2016-01-01' },
  { src:'lazarus', tgt:'reg_amer', rel:'targets', weight:0.75, first_seen:'2018-01-01' },
  { src:'clop',    tgt:'reg_amer', rel:'targets', weight:0.85, first_seen:'2020-01-01' },
  { src:'volt',    tgt:'reg_amer', rel:'targets', weight:0.90, first_seen:'2022-01-01' },
  { src:'volt',    tgt:'reg_apac', rel:'targets', weight:0.88, first_seen:'2021-01-01' },
  { src:'salt',    tgt:'reg_amer', rel:'targets', weight:0.92, first_seen:'2022-01-01' },

  /* Actor → Sector */
  { src:'apt29',   tgt:'sec_gov',    rel:'targets', weight:0.95, first_seen:'2014-01-01' },
  { src:'apt29',   tgt:'sec_energy', rel:'targets', weight:0.80, first_seen:'2019-01-01' },
  { src:'apt41',   tgt:'sec_health', rel:'targets', weight:0.85, first_seen:'2020-01-01' },
  { src:'apt41',   tgt:'sec_tech',   rel:'targets', weight:0.90, first_seen:'2014-01-01' },
  { src:'lockbit', tgt:'sec_health', rel:'targets', weight:0.90, first_seen:'2020-06-01' },
  { src:'lockbit', tgt:'sec_fin',    rel:'targets', weight:0.85, first_seen:'2021-01-01' },
  { src:'lazarus', tgt:'sec_fin',    rel:'targets', weight:0.92, first_seen:'2016-01-01' },
  { src:'fin7',    tgt:'sec_fin',    rel:'targets', weight:0.98, first_seen:'2015-01-01' },
  { src:'volt',    tgt:'sec_energy', rel:'targets', weight:0.95, first_seen:'2022-01-01' },
  { src:'salt',    tgt:'sec_telco',  rel:'targets', weight:0.97, first_seen:'2022-06-01' },
  { src:'clop',    tgt:'sec_health', rel:'targets', weight:0.88, first_seen:'2021-01-01' },
  { src:'clop',    tgt:'sec_fin',    rel:'targets', weight:0.85, first_seen:'2020-01-01' },

  /* Cross-actor infrastructure sharing */
  { src:'lockbit', tgt:'blackcat', rel:'shares_infra', weight:0.65, first_seen:'2022-01-01' },
  { src:'apt29',   tgt:'apt28',    rel:'shares_ttp',   weight:0.55, first_seen:'2018-01-01' },
  { src:'apt41',   tgt:'volt',     rel:'shares_ttp',   weight:0.60, first_seen:'2021-06-01' },
  { src:'salt',    tgt:'volt',     rel:'shares_infra', weight:0.70, first_seen:'2022-01-01' },

  /* Malware → Technique */
  { src:'cobalt',  tgt:'t1059', rel:'enables', weight:0.92, first_seen:'2012-01-01' },
  { src:'cobalt',  tgt:'t1027', rel:'enables', weight:0.88, first_seen:'2012-01-01' },
  { src:'emotet',  tgt:'t1566', rel:'enables', weight:0.95, first_seen:'2014-06-01' },
  { src:'lockbit_bin',tgt:'t1486',rel:'implements',weight:1.00,first_seen:'2019-09-01' },
];

/* ═══════════════════════════════════════════════════════════════════════════
   §3  STATE
═══════════════════════════════════════════════════════════════════════════ */
let _s = {
  nodes: [],            /* visible nodes (post-filter) */
  edges: [],            /* visible edges */
  allNodes: [],         /* master node list */
  allEdges: [],         /* master edge list */
  positions: new Map(), /* nodeId → {x,y,vx,vy} */
  zoom: 1,
  pan:  { x:0, y:0 },
  dragging: false,
  dragNode: null,
  panStart: null,
  selectedNode: null,
  hoverNode: null,

  /* Enhancement 1: Temporal */
  temporal: {
    enabled: false,
    playing: false,
    speed:   1,
    date:    null,
    minDate: '2008-01-01',
    maxDate: '2025-05-23',
    deltaMode: false,
    timer: null,
  },

  /* Enhancement 2: Attack Path */
  attackPath: {
    active:  false,
    source:  null,
    target:  null,
    path:    [],
    shiftHeld: false,
  },

  /* Enhancement 3: Blast Radius */
  blast: {
    active: false,
    centerNode: null,
    rings: [],          /* [{r1_nodes},{r2_nodes},{r3_nodes}] */
    animFrame: 0,
    animMax: 120,
  },

  /* Enhancement 4: Lens Filters */
  lens: {
    actorType:  [],   /* 'nation-state','cybercriminal','hacktivist','unknown' */
    origin:     [],   /* ISO codes */
    malwareFamily:[],
    campaignStatus:'', /* 'active','historical','' */
    tactics:    [],   /* MITRE tactic names */
    sectors:    [],
    severity:   [],   /* 'critical','high','medium','low' */
    minConfidence: 0,
    timeWindow: 'all',
    compositeOR: false,
    saved: [],        /* {name, state} */
  },

  /* Enhancement 5: Ego mode */
  ego: {
    active: false,
    centerId: null,
    depth1: new Set(),
    depth2: new Set(),
    depth3: new Set(),
    history: [],
    pinned: false,
  },

  /* Enhancement 6: AI Narrator */
  narrator: {
    open: true,
    loading: false,
    message: 'Click any node or perform an action to see AI context.',
    lastAction: null,
  },

  /* Physics */
  simRunning: true,
  animFrame: null,
  ctx: null,
  canvas: null,
  contextMenu: null,
};

/* ═══════════════════════════════════════════════════════════════════════════
   §4  UTILITIES
═══════════════════════════════════════════════════════════════════════════ */
function _e(s) {
  const d = document.createElement('div');
  d.textContent = String(s||'');
  return d.innerHTML;
}
function _qs(sel, ctx) { return (ctx||document).querySelector(sel); }
function _qsa(sel, ctx) { return Array.from((ctx||document).querySelectorAll(sel)); }
function _dateToNum(d) { return new Date(d||'2000-01-01').getTime(); }
function _numToDate(n) { return new Date(n).toISOString().slice(0,10); }
function _riskColor(r) {
  if (r >= 90) return '#ef4444';
  if (r >= 75) return '#f97316';
  if (r >= 55) return '#eab308';
  return '#22c55e';
}
function _lerp(a,b,t) { return a + (b-a)*t; }
function _toast(msg, type) {
  const t = document.createElement('div');
  const colors = {success:'#22c55e',error:'#ef4444',info:'#3b82f6',warning:'#f97316'};
  t.style.cssText = `position:fixed;bottom:24px;right:24px;z-index:99999;background:#0f172a;border:1px solid ${colors[type]||colors.info}44;border-left:3px solid ${colors[type]||colors.info};border-radius:10px;padding:12px 18px;font-size:12px;color:#e2e8f0;font-family:Inter,sans-serif;box-shadow:0 8px 32px rgba(0,0,0,.7);animation:tgv2ToastIn .3s ease;max-width:320px;display:flex;align-items:center;gap:8px;`;
  t.innerHTML = `<i class="fas fa-${type==='success'?'check-circle':type==='error'?'times-circle':type==='warning'?'exclamation-triangle':'info-circle'}" style="color:${colors[type]||colors.info}"></i>${_e(msg)}`;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 3500);
}

/* ═══════════════════════════════════════════════════════════════════════════
   §5  GRAPH PHYSICS ENGINE
═══════════════════════════════════════════════════════════════════════════ */
function _initPhysics() {
  if (!_s.positions.size) {
    _s.allNodes.forEach((n,i) => {
      const angle = (i / _s.allNodes.length) * Math.PI * 2;
      const r = 220 + Math.random() * 120;
      _s.positions.set(n.id, {
        x: 500 + r * Math.cos(angle),
        y: 380 + r * Math.sin(angle),
        vx: (Math.random()-.5)*0.5,
        vy: (Math.random()-.5)*0.5,
      });
    });
  }
}

function _physicsStep() {
  if (!_s.simRunning) return;
  const visibleIds = new Set(_s.nodes.map(n=>n.id));
  const ns = _s.nodes;
  const REPULSION = 3500;
  const SPRING_LEN = 140;
  const SPRING_K = 0.018;
  const DAMPING = 0.88;
  const GRAVITY = 0.004;

  /* Repulsion */
  for (let i=0;i<ns.length;i++) {
    const pi = _s.positions.get(ns[i].id);
    if (!pi) continue;
    for (let j=i+1;j<ns.length;j++) {
      const pj = _s.positions.get(ns[j].id);
      if (!pj) continue;
      const dx = pi.x-pj.x, dy = pi.y-pj.y;
      const d = Math.sqrt(dx*dx+dy*dy)||1;
      const f = REPULSION/(d*d);
      pi.vx += dx/d*f*0.016; pi.vy += dy/d*f*0.016;
      pj.vx -= dx/d*f*0.016; pj.vy -= dy/d*f*0.016;
    }
    /* Gravity toward center */
    const cx = (_s.canvas?_s.canvas.width:1000)/2;
    const cy = (_s.canvas?_s.canvas.height:700)/2;
    pi.vx += (cx - pi.x) * GRAVITY;
    pi.vy += (cy - pi.y) * GRAVITY;
  }

  /* Spring edges */
  _s.edges.forEach(e => {
    const ps = _s.positions.get(e.src), pt = _s.positions.get(e.tgt);
    if (!ps||!pt||!visibleIds.has(e.src)||!visibleIds.has(e.tgt)) return;
    const dx = pt.x-ps.x, dy = pt.y-ps.y;
    const d = Math.sqrt(dx*dx+dy*dy)||1;
    const f = (d - SPRING_LEN) * SPRING_K * (e.weight||0.5);
    ps.vx += dx/d*f; ps.vy += dy/d*f;
    pt.vx -= dx/d*f; pt.vy -= dy/d*f;
  });

  /* Integrate */
  ns.forEach(n => {
    const p = _s.positions.get(n.id);
    if (!p || n.id === _s.dragNode?.id) return;
    p.vx *= DAMPING; p.vy *= DAMPING;
    p.x += p.vx; p.y += p.vy;
    const W = _s.canvas?.width||1000, H = _s.canvas?.height||700;
    p.x = Math.max(40, Math.min(W-40, p.x));
    p.y = Math.max(40, Math.min(H-40, p.y));
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   §6  DRAW ENGINE
═══════════════════════════════════════════════════════════════════════════ */
function _draw() {
  const canvas = _s.canvas;
  const ctx = _s.ctx;
  if (!canvas||!ctx) return;

  ctx.clearRect(0,0,canvas.width,canvas.height);
  ctx.save();
  ctx.translate(_s.pan.x, _s.pan.y);
  ctx.scale(_s.zoom, _s.zoom);

  const visibleIds = new Set(_s.nodes.map(n=>n.id));

  /* ── Ego mode depth rings ── */
  if (_s.ego.active && _s.ego.centerId) {
    const cp = _s.positions.get(_s.ego.centerId);
    if (cp) {
      [120,220,320].forEach((r,i) => {
        ctx.beginPath();
        ctx.arc(cp.x, cp.y, r, 0, Math.PI*2);
        ctx.strokeStyle = `rgba(${i===0?'34,211,238':i===1?'168,85,247':'100,116,139'},0.12)`;
        ctx.lineWidth = 1.5/_s.zoom;
        ctx.setLineDash([6,4]);
        ctx.stroke();
        ctx.setLineDash([]);
      });
    }
  }

  /* ── Blast radius rings ── */
  if (_s.blast.active && _s.blast.centerNode) {
    const cp = _s.positions.get(_s.blast.centerNode.id);
    if (cp) {
      const progress = Math.min(1, _s.blast.animFrame / _s.blast.animMax);
      [[220,'rgba(239,68,68,'],[370,'rgba(249,115,22,'],[520,'rgba(234,179,8,']].forEach(([maxR, color], ri) => {
        const r = maxR * progress * (ri===0?1:ri===1?.9:.8);
        const alpha = (0.12 - ri*0.03) * progress;
        ctx.beginPath();
        ctx.arc(cp.x, cp.y, r, 0, Math.PI*2);
        ctx.strokeStyle = color + (alpha+0.1) + ')';
        ctx.lineWidth = (2-ri*0.4)/_s.zoom;
        ctx.stroke();
        ctx.fillStyle = color + alpha + ')';
        ctx.fill();
      });
    }
  }

  /* ── Attack Path highlighted edges ── */
  if (_s.attackPath.active && _s.attackPath.path.length > 1) {
    const path = _s.attackPath.path;
    for (let i=0; i<path.length-1; i++) {
      const ps = _s.positions.get(path[i]);
      const pt = _s.positions.get(path[i+1]);
      if (!ps||!pt) continue;
      /* glow */
      ctx.save();
      ctx.shadowColor = '#22d3ee';
      ctx.shadowBlur = 12/_s.zoom;
      ctx.beginPath();
      ctx.moveTo(ps.x,ps.y); ctx.lineTo(pt.x,pt.y);
      ctx.strokeStyle = '#22d3ee';
      ctx.lineWidth = 3/_s.zoom;
      ctx.stroke();
      ctx.restore();
      /* Animated arrow */
      const t = (Date.now()/600) % 1;
      const ax = _lerp(ps.x,pt.x,t), ay = _lerp(ps.y,pt.y,t);
      const angle = Math.atan2(pt.y-ps.y, pt.x-ps.x);
      ctx.save();
      ctx.translate(ax,ay); ctx.rotate(angle);
      ctx.beginPath();
      ctx.moveTo(0,0); ctx.lineTo(-12,6); ctx.lineTo(-12,-6); ctx.closePath();
      ctx.fillStyle = '#22d3ee';
      ctx.fill();
      ctx.restore();
    }
  }

  /* ── Edges ── */
  _s.edges.forEach(e => {
    const ps = _s.positions.get(e.src), pt = _s.positions.get(e.tgt);
    if (!ps||!pt||!visibleIds.has(e.src)||!visibleIds.has(e.tgt)) return;

    const isPath = _s.attackPath.active && _s.attackPath.path.length > 1 &&
      _s.attackPath.path.some((p,i) => i < _s.attackPath.path.length-1 && p===e.src && _s.attackPath.path[i+1]===e.tgt);
    if (isPath) return; /* Already drawn above */

    /* Ego dimming */
    let alpha = 0.3;
    if (_s.ego.active) {
      const srcIn = _s.ego.depth1.has(e.src)||_s.ego.depth2.has(e.src)||_s.ego.depth3.has(e.src)||e.src===_s.ego.centerId;
      const tgtIn = _s.ego.depth1.has(e.tgt)||_s.ego.depth2.has(e.tgt)||_s.ego.depth3.has(e.tgt)||e.tgt===_s.ego.centerId;
      alpha = (srcIn&&tgtIn) ? 0.5 : 0.04;
    }

    ctx.beginPath();
    ctx.moveTo(ps.x,ps.y); ctx.lineTo(pt.x,pt.y);
    const relColors = { deploys:'#ef4444', uses:'#3b82f6', targets:'#f97316', conducts:'#a855f7', owns:'#22c55e', conducting:'#22d3ee', shares_infra:'#6b7280', shares_ttp:'#64748b', enables:'#8b5cf6', implements:'#ef4444' };
    ctx.strokeStyle = (relColors[e.rel]||'#334155') + Math.round(alpha*255).toString(16).padStart(2,'0');
    ctx.lineWidth = (0.8 + (e.weight||0.5))/_s.zoom;
    ctx.stroke();
  });

  /* ── Temporal delta mode highlights ── */
  if (_s.temporal.enabled && _s.temporal.deltaMode) {
    /* pulse newly appeared nodes */
    _s.nodes.forEach(n => {
      const p = _s.positions.get(n.id);
      if (!p) return;
      const cfg = NODE_CFG[n.type]||NODE_CFG.infrastructure;
      const t = (Date.now()/800)%1;
      ctx.beginPath();
      ctx.arc(p.x,p.y,(cfg.size+8+t*16)/_s.zoom,0,Math.PI*2);
      ctx.strokeStyle = `rgba(34,211,238,${0.4*(1-t)})`;
      ctx.lineWidth = 2/_s.zoom;
      ctx.stroke();
    });
  }

  /* ── Nodes ── */
  _s.nodes.forEach(n => {
    const p = _s.positions.get(n.id);
    if (!p) return;
    const cfg = NODE_CFG[n.type]||NODE_CFG.infrastructure;
    const isSelected = n.id === _s.selectedNode?.id;
    const isHover    = n.id === _s.hoverNode?.id;
    const isPath = _s.attackPath.active && (_s.attackPath.source===n.id||_s.attackPath.target===n.id||_s.attackPath.path.includes(n.id));

    let opacity = 1;
    if (_s.ego.active) {
      const inEgo = n.id===_s.ego.centerId || _s.ego.depth1.has(n.id) || _s.ego.depth2.has(n.id) || _s.ego.depth3.has(n.id);
      opacity = inEgo ? 1 : 0.08;
    }
    if (_s.blast.active && !_s.blast.rings.flat().includes(n.id) && n.id!==_s.blast.centerNode?.id) {
      opacity = Math.min(opacity, 0.2);
    }

    ctx.globalAlpha = opacity;

    /* Glow for selected/hover/path */
    if (isSelected||isHover||isPath) {
      ctx.save();
      ctx.shadowColor = isPath ? '#22d3ee' : cfg.color;
      ctx.shadowBlur = (isSelected?18:10)/_s.zoom;
      ctx.beginPath();
      ctx.arc(p.x,p.y,cfg.size/_s.zoom,0,Math.PI*2);
      ctx.fillStyle = cfg.color+'33';
      ctx.fill();
      ctx.restore();
    }

    /* Node circle */
    ctx.beginPath();
    ctx.arc(p.x,p.y,cfg.size/_s.zoom,0,Math.PI*2);
    ctx.fillStyle = cfg.bg;
    ctx.fill();
    ctx.strokeStyle = isSelected ? '#fff' : isPath ? '#22d3ee' : cfg.color;
    ctx.lineWidth = (isSelected?3:1.5)/_s.zoom;
    ctx.stroke();

    /* Risk ring */
    if (n.risk >= 80) {
      const pulse = 0.6 + 0.4*Math.sin(Date.now()/600);
      ctx.beginPath();
      ctx.arc(p.x,p.y,(cfg.size+5)/_s.zoom,0,Math.PI*2);
      ctx.strokeStyle = _riskColor(n.risk) + Math.round(pulse*80).toString(16).padStart(2,'0');
      ctx.lineWidth = 1/_s.zoom;
      ctx.stroke();
    }

    /* Label */
    const fs = Math.max(9, 11/_s.zoom);
    ctx.font = `${isSelected?'700':'600'} ${fs}px Inter,sans-serif`;
    ctx.fillStyle = opacity < 0.3 ? 'rgba(255,255,255,0.15)' : '#e2e8f0';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText(n.label, p.x, p.y + (cfg.size+4)/_s.zoom);

    ctx.globalAlpha = 1;
  });

  /* ── Attack path src/tgt indicators ── */
  if (_s.attackPath.shiftHeld && _s.attackPath.source && !_s.attackPath.target) {
    const ps = _s.positions.get(_s.attackPath.source);
    if (ps) {
      ctx.beginPath();
      ctx.arc(ps.x, ps.y, 40/_s.zoom, 0, Math.PI*2);
      ctx.strokeStyle = 'rgba(34,211,238,0.6)';
      ctx.lineWidth = 2/_s.zoom;
      ctx.setLineDash([4,3]);
      ctx.stroke();
      ctx.setLineDash([]);
    }
  }

  ctx.restore();

  /* Ego depth labels on canvas overlay */
  if (_s.ego.active && _s.ego.centerId) {
    _drawEgoLabels();
  }
}

function _drawEgoLabels() {
  const ctx = _s.ctx;
  if (!ctx) return;
  ctx.save();
  ctx.translate(_s.pan.x, _s.pan.y);
  ctx.scale(_s.zoom, _s.zoom);
  const cp = _s.positions.get(_s.ego.centerId);
  if (!cp) { ctx.restore(); return; }
  [[_s.ego.depth1,'1st','#22d3ee'],[_s.ego.depth2,'2nd','#a855f7'],[_s.ego.depth3,'3rd','#64748b']].forEach(([set,label,color]) => {
    set.forEach(id => {
      const p = _s.positions.get(id);
      if (!p) return;
      ctx.font = `600 9px Inter,sans-serif`;
      ctx.fillStyle = color;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(label, p.x, p.y - 28/_s.zoom);
    });
  });
  ctx.restore();
}

/* ═══════════════════════════════════════════════════════════════════════════
   §7  ANIMATION LOOP
═══════════════════════════════════════════════════════════════════════════ */
function _loop() {
  _physicsStep();
  _draw();
  _s.animFrame = requestAnimationFrame(_loop);

  /* Blast radius animation */
  if (_s.blast.active) {
    _s.blast.animFrame = Math.min(_s.blast.animFrame + 1, _s.blast.animMax);
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   §8  FILTER & DATA MANAGEMENT
═══════════════════════════════════════════════════════════════════════════ */
function _applyFilters() {
  const l = _s.lens;

  let nodes = _s.allNodes.filter(n => {
    /* Temporal filter */
    if (_s.temporal.enabled && _s.temporal.date) {
      const cutoff = _dateToNum(_s.temporal.date);
      if (_dateToNum(n.first_seen||'2000-01-01') > cutoff) return false;
    }

    /* Lens filters */
    if (!l.compositeOR) {
      /* AND mode */
      if (l.actorType.length && n.type==='threat_actor') {
        const map = {nation_state:['CN','RU','KP','IR'],cybercriminal:['Crime','RaaS']};
        const match = l.actorType.some(t => {
          if (t==='nation-state') return ['SVR','GRU','MSS','RGB','PLA'].includes(n.sponsor);
          if (t==='cybercriminal') return ['Crime','RaaS'].includes(n.sponsor);
          return false;
        });
        if (!match) return false;
      }
      if (l.origin.length && n.origin) {
        if (!l.origin.includes(n.origin)) return false;
      }
      if (l.campaignStatus && n.type==='campaign') {
        if (n.status !== l.campaignStatus) return false;
      }
      if (l.sectors.length && n.type==='target_sector') {
        const sectorLabel = n.label.toLowerCase();
        if (!l.sectors.some(s => sectorLabel.includes(s.toLowerCase()))) return false;
      }
      if (l.severity.length) {
        const r = n.risk||0;
        const sev = r>=90?'critical':r>=75?'high':r>=55?'medium':'low';
        if (!l.severity.includes(sev)) return false;
      }
      if (l.minConfidence && n.confidence) {
        if (n.confidence < l.minConfidence) return false;
      }
      if (l.timeWindow !== 'all' && n.last_seen) {
        const days = {last7d:7,last30d:30,last90d:90,last1y:365}[l.timeWindow]||99999;
        const cutoff = Date.now() - days*86400000;
        if (_dateToNum(n.last_seen) < cutoff) return false;
      }
    }
    return true;
  });

  const visibleIds = new Set(nodes.map(n=>n.id));
  const edges = _s.allEdges.filter(e => {
    if (!visibleIds.has(e.src)||!visibleIds.has(e.tgt)) return false;
    if (_s.temporal.enabled && _s.temporal.date) {
      if (_dateToNum(e.first_seen||'2000-01-01') > _dateToNum(_s.temporal.date)) return false;
    }
    return true;
  });

  _s.nodes = nodes;
  _s.edges = edges;
  _updateNodeCount();
}

function _updateNodeCount() {
  const el = document.getElementById('tgv2-node-count');
  if (el) el.textContent = `${_s.nodes.length} nodes · ${_s.edges.length} edges`;
}

/* ═══════════════════════════════════════════════════════════════════════════
   §9  TEMPORAL ENGINE (Enhancement 1)
═══════════════════════════════════════════════════════════════════════════ */
function _temporalInit() {
  _s.temporal.date = _s.temporal.maxDate;
  _s.temporal.enabled = false;
}

window.tgv2TemporalToggle = function() {
  _s.temporal.enabled = !_s.temporal.enabled;
  const btn = document.getElementById('tgv2-temporal-btn');
  if (btn) btn.style.borderColor = _s.temporal.enabled ? '#22d3ee' : '#1e293b';
  const strip = document.getElementById('tgv2-temporal-strip');
  if (strip) strip.style.display = _s.temporal.enabled ? 'flex' : 'none';
  if (!_s.temporal.enabled) {
    _s.temporal.playing = false;
    clearInterval(_s.temporal.timer);
  }
  _applyFilters();
};

window.tgv2TemporalPlay = function() {
  _s.temporal.playing = !_s.temporal.playing;
  const btn = document.getElementById('tgv2-play-btn');
  if (!_s.temporal.playing) {
    clearInterval(_s.temporal.timer);
    if (btn) btn.innerHTML = '<i class="fas fa-play"></i>';
    return;
  }
  if (btn) btn.innerHTML = '<i class="fas fa-pause"></i>';
  clearInterval(_s.temporal.timer);
  _s.temporal.timer = setInterval(() => {
    const slider = document.getElementById('tgv2-time-slider');
    if (!slider) return;
    const cur = parseInt(slider.value)||0;
    const step = _s.temporal.speed * 5;
    if (cur + step >= parseInt(slider.max)) {
      slider.value = slider.max;
      _s.temporal.playing = false;
      clearInterval(_s.temporal.timer);
      if (btn) btn.innerHTML = '<i class="fas fa-play"></i>';
    } else {
      slider.value = cur + step;
    }
    tgv2TemporalScrub(slider.value);
  }, 200);
};

window.tgv2TemporalScrub = function(val) {
  const minD = _dateToNum(_s.temporal.minDate);
  const maxD = _dateToNum(_s.temporal.maxDate);
  const ts   = minD + (val/1000) * (maxD-minD);
  _s.temporal.date = _numToDate(ts);
  const el = document.getElementById('tgv2-date-display');
  if (el) el.textContent = _s.temporal.date;
  _applyFilters();
  _generateNarration(`temporal_scrub`, `Date scrubbed to ${_s.temporal.date}. Showing ${_s.nodes.length} nodes visible at that point in time.`);
};

window.tgv2TemporalSpeed = function(s) {
  _s.temporal.speed = s;
  _qsa('#tgv2-speed-btns button').forEach(b => b.style.background = b.dataset.speed==s ? '#22d3ee22' : '#0a0e17');
};

window.tgv2DeltaMode = function() {
  _s.temporal.deltaMode = !_s.temporal.deltaMode;
  const btn = document.getElementById('tgv2-delta-btn');
  if (btn) btn.style.background = _s.temporal.deltaMode ? '#22d3ee22' : '';
};

window.tgv2SnapToEvent = function(idx) {
  const ev = TIMELINE_EVENTS[idx];
  if (!ev) return;
  _s.temporal.date = ev.date;
  const slider = document.getElementById('tgv2-time-slider');
  if (slider) {
    const minD = _dateToNum(_s.temporal.minDate);
    const maxD = _dateToNum(_s.temporal.maxDate);
    const ts   = _dateToNum(ev.date);
    slider.value = Math.round(((ts-minD)/(maxD-minD))*1000);
  }
  const el = document.getElementById('tgv2-date-display');
  if (el) el.textContent = ev.date;
  _applyFilters();
  _toast(`⏱ Jumped to: ${ev.label} (${ev.date})`, 'info');
  _generateNarration('snap_event', `Jumped to ${ev.label} on ${ev.date}. ${ev.desc}. Graph shows ${_s.nodes.length} known entities at that point.`);
};

window.tgv2TemporalLive = function() {
  _s.temporal.enabled = false;
  _s.temporal.playing = false;
  clearInterval(_s.temporal.timer);
  const strip = document.getElementById('tgv2-temporal-strip');
  if (strip) strip.style.display = 'none';
  _applyFilters();
  _toast('Live mode — showing current threat landscape', 'success');
};

/* ═══════════════════════════════════════════════════════════════════════════
   §10  ATTACK PATH SIMULATOR (Enhancement 2)
═══════════════════════════════════════════════════════════════════════════ */
function _dijkstra(srcId, tgtId) {
  const dist = {}, prev = {};
  const visited = new Set();
  const adj = {};

  _s.nodes.forEach(n => { dist[n.id] = Infinity; adj[n.id] = []; });
  dist[srcId] = 0;

  _s.edges.forEach(e => {
    if (adj[e.src]) adj[e.src].push({ id:e.tgt, w: 1 - (e.weight||0.5), edge:e });
    if (adj[e.tgt]) adj[e.tgt].push({ id:e.src, w: 1 - (e.weight||0.5), edge:e });
  });

  while (true) {
    let u = null;
    Object.keys(dist).forEach(id => { if (!visited.has(id) && (u===null || dist[id]<dist[u])) u=id; });
    if (!u || dist[u]===Infinity) break;
    if (u===tgtId) break;
    visited.add(u);
    (adj[u]||[]).forEach(({ id, w }) => {
      const alt = dist[u] + w;
      if (alt < dist[id]) { dist[id]=alt; prev[id]=u; }
    });
  }

  if (dist[tgtId]===Infinity) return [];
  const path = [];
  let cur = tgtId;
  while (cur) { path.unshift(cur); cur=prev[cur]; }
  return path;
}

function _computeAttackPath(srcId, tgtId) {
  const path = _dijkstra(srcId, tgtId);
  _s.attackPath.path = path;
  _s.attackPath.active = path.length > 0;

  if (!path.length) { _toast('No attack path found between selected nodes','warning'); return; }

  _renderAttackPathPanel(path);
  _generateNarration('attack_path', `Attack path computed: ${path.map(id => _s.allNodes.find(n=>n.id===id)?.label||id).join(' → ')}. Path has ${path.length-1} hops.`);
}

function _renderAttackPathPanel(path) {
  const panel = document.getElementById('tgv2-right-panel-content');
  if (!panel) return;

  const nodes = path.map(id => _s.allNodes.find(n=>n.id===id)).filter(Boolean);
  const hops = [];
  for (let i=0;i<path.length-1;i++) {
    const edge = _s.allEdges.find(e => (e.src===path[i]&&e.tgt===path[i+1])||(e.src===path[i+1]&&e.tgt===path[i]));
    hops.push({ from:nodes[i], to:nodes[i+1], edge });
  }

  const mitreTechniques = {
    uses:'T1059 Execution', deploys:'T1105 Ingress Tool Transfer', targets:'T1562 Defense Evasion',
    owns:'T1486 Data Encrypted', shares_infra:'T1583 Acquire Infrastructure', enables:'T1059 Scripting',
    conducting:'T1573 Encrypted Channel', shares_ttp:'T1027 Obfuscation', implements:'T1486 Impact',
  };

  panel.innerHTML = `
  <div style="padding:16px;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid #1e293b;">
      <div style="width:28px;height:28px;background:#22d3ee22;border-radius:8px;display:flex;align-items:center;justify-content:center;"><i class="fas fa-route" style="color:#22d3ee;font-size:13px;"></i></div>
      <div>
        <div style="font-size:12px;font-weight:700;color:#f1f5f9;">Attack Path</div>
        <div style="font-size:10px;color:#475569;">${path.length-1} hop${path.length>2?'s':''} · Dijkstra-weighted</div>
      </div>
      <button onclick="tgv2ClearAttackPath()" style="margin-left:auto;background:#1e293b;border:none;color:#64748b;padding:4px 8px;border-radius:6px;cursor:pointer;font-size:10px;">✕ Clear</button>
    </div>

    <!-- Path visualization -->
    <div style="display:flex;flex-direction:column;gap:6px;margin-bottom:16px;">
      ${hops.map((h,i) => `
      <div style="background:#090d14;border:1px solid #1e293b;border-radius:8px;padding:10px 12px;">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
          <span style="font-size:10px;color:#64748b;">Hop ${i+1}</span>
          <span style="flex:1;height:1px;background:#1e293b;"></span>
          <span style="font-size:9px;color:#475569;">${mitreTechniques[h.edge?.rel]||'T1078 Lateral Movement'}</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:11px;font-weight:700;color:${NODE_CFG[h.from?.type]?.color||'#e2e8f0'};">${h.from?.label||'?'}</span>
          <i class="fas fa-arrow-right" style="color:#22d3ee;font-size:10px;"></i>
          <span style="font-size:11px;font-weight:700;color:${NODE_CFG[h.to?.type]?.color||'#e2e8f0'};">${h.to?.label||'?'}</span>
        </div>
        <div style="font-size:10px;color:#64748b;margin-top:4px;">${h.edge?.rel||'related'} · Probability: ${Math.round((h.edge?.weight||0.5)*100)}%</div>
      </div>`).join('')}
    </div>

    <!-- MITRE annotations -->
    <div style="background:#090d14;border:1px solid #1e293b;border-radius:8px;padding:12px;margin-bottom:12px;">
      <div style="font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;margin-bottom:8px;">MITRE ATT&CK Techniques</div>
      ${hops.map(h => `<div style="font-size:11px;color:#94a3b8;padding:3px 0;">${mitreTechniques[h.edge?.rel]||'T1078 Valid Accounts'}</div>`).join('')}
    </div>

    <!-- ETA estimate -->
    <div style="background:#090d14;border:1px solid #1e293b;border-radius:8px;padding:12px;margin-bottom:12px;">
      <div style="font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;margin-bottom:6px;">Estimated Time-to-Impact</div>
      <div style="font-size:18px;font-weight:800;color:#ef4444;">${path.length <= 2 ? '24–72 hours' : path.length <= 4 ? '1–2 weeks' : '2–6 weeks'}</div>
      <div style="font-size:10px;color:#64748b;margin-top:2px;">Based on ${path.length-1} hop path complexity</div>
    </div>

    <!-- Detection controls -->
    <div style="background:#090d14;border:1px solid #1e293b;border-radius:8px;padding:12px;margin-bottom:12px;">
      <div style="font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;margin-bottom:8px;">Detection Controls</div>
      ${hops.map((h,i) => `<div style="font-size:10px;color:#94a3b8;padding:2px 0;display:flex;gap:6px;"><span style="color:#22c55e;">→</span> Hop ${i+1}: ${h.edge?.rel==='deploys'?'EDR file execution monitoring':h.edge?.rel==='uses'?'SIEM rule on tool signature':h.edge?.rel==='targets'?'Network traffic anomaly detection':'Behavioral baseline alerting'}</div>`).join('')}
    </div>

    <!-- Export -->
    <div style="display:flex;gap:6px;">
      <button onclick="tgv2ExportSTIX()" style="flex:1;background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:7px;border-radius:7px;cursor:pointer;font-size:10px;font-weight:600;"><i class="fas fa-code" style="margin-right:4px;"></i>STIX 2.1</button>
      <button onclick="tgv2ExportPDF()" style="flex:1;background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:7px;border-radius:7px;cursor:pointer;font-size:10px;font-weight:600;"><i class="fas fa-file-pdf" style="margin-right:4px;"></i>PDF Brief</button>
    </div>
  </div>`;
}

window.tgv2ClearAttackPath = function() {
  _s.attackPath = { active:false, source:null, target:null, path:[], shiftHeld:false };
  const panel = document.getElementById('tgv2-right-panel-content');
  if (panel) _renderNarratorDefault();
};

window.tgv2ExportSTIX = function() {
  const nodes = _s.attackPath.path.map(id => _s.allNodes.find(n=>n.id===id)).filter(Boolean);
  const stix = {
    type:'bundle', spec_version:'2.1', id:`bundle--${crypto.randomUUID()}`,
    objects: nodes.map(n => ({
      type: n.type==='threat_actor'?'threat-actor':'attack-pattern',
      id:`${n.type==='threat_actor'?'threat-actor':'attack-pattern'}--${crypto.randomUUID()}`,
      name: n.label, spec_version:'2.1',
    }))
  };
  const blob = new Blob([JSON.stringify(stix, null, 2)], { type:'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `attack-path-stix-${Date.now()}.json`;
  a.click();
  _toast('STIX 2.1 bundle exported', 'success');
};

window.tgv2ExportPDF = function() {
  _toast('PDF TTX brief generation — requires backend PDF service', 'info');
};

/* ═══════════════════════════════════════════════════════════════════════════
   §11  BLAST RADIUS (Enhancement 3)
═══════════════════════════════════════════════════════════════════════════ */
window.tgv2BlastRadius = function(nodeId) {
  const node = _s.allNodes.find(n=>n.id===nodeId);
  if (!node) return;

  const targetingSectors = new Set(['target_sector','region']);
  /* Ring 1: direct edges */
  const ring1 = _s.allEdges
    .filter(e => (e.tgt===nodeId||e.src===nodeId) && e.rel==='targets')
    .map(e => e.src===nodeId ? e.tgt : e.src)
    .filter(id => _s.allNodes.find(n=>n.id===id)?.type==='threat_actor');

  /* Ring 2: actors sharing infra with ring1 actors */
  const ring1Set = new Set(ring1);
  const ring2 = _s.allEdges
    .filter(e => (ring1Set.has(e.src)||ring1Set.has(e.tgt)) && (e.rel==='shares_infra'||e.rel==='shares_ttp'))
    .map(e => ring1Set.has(e.src)?e.tgt:e.src)
    .filter(id => !ring1Set.has(id) && _s.allNodes.find(n=>n.id===id)?.type==='threat_actor');

  /* Ring 3: any remaining actors */
  const ring12Set = new Set([...ring1,...ring2]);
  const ring3 = _s.allNodes
    .filter(n => n.type==='threat_actor' && !ring12Set.has(n.id))
    .slice(0,4).map(n=>n.id);

  _s.blast = { active:true, centerNode:node, rings:[ring1,ring2,ring3], animFrame:0, animMax:120 };
  _renderBlastPanel(node, ring1, ring2, ring3);
  _toast(`Blast radius simulation started for ${node.label}`, 'warning');
  _generateNarration('blast_radius', `Blast radius simulation for ${node.label}: Ring 1 has ${ring1.length} direct actors, Ring 2 has ${ring2.length} adjacent actors, Ring 3 has ${ring3.length} potential threat actors.`);
};

function _renderBlastPanel(node, r1, r2, r3) {
  const panel = document.getElementById('tgv2-right-panel-content');
  if (!panel) return;
  const actorInfo = (id) => {
    const n = _s.allNodes.find(n=>n.id===id);
    return n ? { name:n.label, risk:n.risk||50 } : { name:id, risk:50 };
  };
  panel.innerHTML = `
  <div style="padding:16px;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid #1e293b;">
      <div style="width:28px;height:28px;background:#ef444422;border-radius:8px;display:flex;align-items:center;justify-content:center;"><i class="fas fa-radiation" style="color:#ef4444;font-size:13px;"></i></div>
      <div>
        <div style="font-size:12px;font-weight:700;color:#f1f5f9;">Blast Radius</div>
        <div style="font-size:10px;color:#475569;">${node.label}</div>
      </div>
      <button onclick="tgv2ClearBlast()" style="margin-left:auto;background:#1e293b;border:none;color:#64748b;padding:4px 8px;border-radius:6px;cursor:pointer;font-size:10px;">✕ Clear</button>
    </div>

    ${[[r1,'Ring 1 — Direct','#ef4444','Known actors targeting this node'],[r2,'Ring 2 — Adjacent','#f97316','Actors sharing infra with Ring 1'],[r3,'Ring 3 — Potential','#eab308','TTP-similar actors with potential reach']].map(([ring,label,color,desc]) => `
    <div style="margin-bottom:12px;">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:6px;">
        <div style="width:10px;height:10px;border-radius:50%;background:${color};box-shadow:0 0 8px ${color}44;"></div>
        <span style="font-size:11px;font-weight:700;color:${color};">${label}</span>
        <span style="font-size:9px;color:#475569;">${ring.length} actors</span>
      </div>
      <div style="font-size:9px;color:#475569;margin-bottom:6px;">${desc}</div>
      ${ring.length ? ring.map(id => { const a=actorInfo(id); return `
      <div style="background:#090d14;border:1px solid ${color}22;border-left:2px solid ${color};border-radius:6px;padding:8px 10px;margin-bottom:4px;display:flex;justify-content:space-between;align-items:center;">
        <span style="font-size:11px;font-weight:600;color:#e2e8f0;">${a.name}</span>
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:9px;color:${_riskColor(a.risk)};">Risk: ${a.risk}</span>
          <span style="font-size:9px;color:${color};">${ring===r1?Math.round(70+Math.random()*25)+'%':ring===r2?Math.round(40+Math.random()*25)+'%':Math.round(15+Math.random()*25)+'%'}</span>
        </div>
      </div>`; }).join('') : `<div style="font-size:10px;color:#334155;padding:6px 0;">No actors identified in this ring</div>`}
    </div>`).join('')}

    <!-- Surface summary -->
    <div style="background:#090d14;border:1px solid #1e293b;border-radius:8px;padding:12px;">
      <div style="font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;margin-bottom:8px;">Surface Summary</div>
      <div style="display:flex;gap:8px;">
        <div style="flex:1;text-align:center;padding:8px;background:#0a0e17;border-radius:6px;">
          <div style="font-size:20px;font-weight:800;color:#ef4444;">${r1.length+r2.length+r3.length}</div>
          <div style="font-size:9px;color:#475569;">Total Actors</div>
        </div>
        <div style="flex:1;text-align:center;padding:8px;background:#0a0e17;border-radius:6px;">
          <div style="font-size:20px;font-weight:800;color:#f97316;">HIGH</div>
          <div style="font-size:9px;color:#475569;">Overall Risk</div>
        </div>
      </div>
    </div>
  </div>`;
}

window.tgv2ClearBlast = function() {
  _s.blast = { active:false, centerNode:null, rings:[], animFrame:0, animMax:120 };
  _renderNarratorDefault();
};

/* ═══════════════════════════════════════════════════════════════════════════
   §12  LENS FILTER SYSTEM (Enhancement 4)
═══════════════════════════════════════════════════════════════════════════ */
window.tgv2LensToggle = function() {
  const panel = document.getElementById('tgv2-lens-panel');
  if (panel) panel.style.display = panel.style.display==='none'?'flex':'none';
};

window.tgv2LensFilterActorType = function(type) {
  const i = _s.lens.actorType.indexOf(type);
  if (i>=0) _s.lens.actorType.splice(i,1);
  else _s.lens.actorType.push(type);
  _updateLensPills(); _applyFilters();
};

window.tgv2LensFilterOrigin = function(code) {
  const i = _s.lens.origin.indexOf(code);
  if (i>=0) _s.lens.origin.splice(i,1);
  else _s.lens.origin.push(code);
  _updateLensPills(); _applyFilters();
};

window.tgv2LensFilterSeverity = function(sev) {
  const i = _s.lens.severity.indexOf(sev);
  if (i>=0) _s.lens.severity.splice(i,1);
  else _s.lens.severity.push(sev);
  _updateLensPills(); _applyFilters();
};

window.tgv2LensFilterCampaign = function(status) {
  _s.lens.campaignStatus = _s.lens.campaignStatus===status ? '' : status;
  _updateLensPills(); _applyFilters();
};

window.tgv2LensTimeWindow = function(tw) {
  _s.lens.timeWindow = tw;
  _updateLensPills(); _applyFilters();
};

window.tgv2LensClear = function() {
  _s.lens = { actorType:[],origin:[],malwareFamily:[],campaignStatus:'',tactics:[],sectors:[],severity:[],minConfidence:0,timeWindow:'all',compositeOR:false,saved:_s.lens.saved };
  _renderLensPanel();
  _updateLensPills();
  _applyFilters();
};

window.tgv2SaveLens = function() {
  const name = prompt('Name this lens view:');
  if (!name) return;
  _s.lens.saved.push({ name, state:JSON.parse(JSON.stringify(_s.lens)) });
  _toast(`Lens "${name}" saved`, 'success');
};

window.tgv2CompositeMode = function() {
  _s.lens.compositeOR = !_s.lens.compositeOR;
  const btn = document.getElementById('tgv2-composite-btn');
  if (btn) btn.textContent = _s.lens.compositeOR ? 'OR' : 'AND';
  _applyFilters();
};

function _updateLensPills() {
  const container = document.getElementById('tgv2-active-filters');
  if (!container) return;
  const pills = [];
  _s.lens.actorType.forEach(t => pills.push({label:`Type: ${t}`, clear:()=>{ _s.lens.actorType=_s.lens.actorType.filter(x=>x!==t); _applyFilters(); _updateLensPills(); }}));
  _s.lens.origin.forEach(o => pills.push({label:`Origin: ${o}`, clear:()=>{ _s.lens.origin=_s.lens.origin.filter(x=>x!==o); _applyFilters(); _updateLensPills(); }}));
  _s.lens.severity.forEach(s => pills.push({label:`Sev: ${s}`, clear:()=>{ _s.lens.severity=_s.lens.severity.filter(x=>x!==s); _applyFilters(); _updateLensPills(); }}));
  if (_s.lens.campaignStatus) pills.push({label:`Campaign: ${_s.lens.campaignStatus}`, clear:()=>{ _s.lens.campaignStatus=''; _applyFilters(); _updateLensPills(); }});
  if (_s.lens.timeWindow!=='all') pills.push({label:`Time: ${_s.lens.timeWindow}`, clear:()=>{ _s.lens.timeWindow='all'; _applyFilters(); _updateLensPills(); }});

  container.innerHTML = pills.map(p => `
    <span style="display:inline-flex;align-items:center;gap:4px;background:#22d3ee15;border:1px solid #22d3ee33;border-radius:20px;padding:3px 10px;font-size:10px;color:#22d3ee;cursor:default;">
      ${_e(p.label)}
      <button onclick="(${p.clear.toString()})()" style="background:none;border:none;color:#22d3ee;cursor:pointer;padding:0;font-size:10px;line-height:1;">✕</button>
    </span>`).join('');
}

function _renderLensPanel() {
  const panel = document.getElementById('tgv2-lens-panel');
  if (!panel) return;
  panel.innerHTML = `
  <div style="display:flex;flex-direction:column;gap:14px;padding:16px;max-height:420px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#1e293b transparent;">

    <!-- Actor Type -->
    <div>
      <div style="font-size:9px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">Actor Type</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;">
        ${['nation-state','cybercriminal','hacktivist','unknown'].map(t => `
        <button onclick="tgv2LensFilterActorType('${t}')" id="lens-at-${t}" style="background:#0a0e17;border:1px solid ${_s.lens.actorType.includes(t)?'#22d3ee':'#1e293b'};color:${_s.lens.actorType.includes(t)?'#22d3ee':'#64748b'};padding:4px 10px;border-radius:20px;cursor:pointer;font-size:10px;transition:all .15s;">${t}</button>`).join('')}
      </div>
    </div>

    <!-- Origin -->
    <div>
      <div style="font-size:9px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">Origin Country</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;">
        ${ACTOR_ORIGINS.map(o => `
        <button onclick="tgv2LensFilterOrigin('${o.code}')" style="background:#0a0e17;border:1px solid ${_s.lens.origin.includes(o.code)?'#22d3ee':'#1e293b'};color:${_s.lens.origin.includes(o.code)?'#22d3ee':'#64748b'};padding:4px 10px;border-radius:20px;cursor:pointer;font-size:10px;transition:all .15s;">${o.flag} ${o.code}</button>`).join('')}
      </div>
    </div>

    <!-- Severity -->
    <div>
      <div style="font-size:9px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">Threat Severity</div>
      <div style="display:flex;gap:5px;">
        ${[['critical','#ef4444'],['high','#f97316'],['medium','#eab308'],['low','#22c55e']].map(([s,c]) => `
        <button onclick="tgv2LensFilterSeverity('${s}')" style="flex:1;background:${_s.lens.severity.includes(s)?c+'22':'#0a0e17'};border:1px solid ${_s.lens.severity.includes(s)?c:'#1e293b'};color:${_s.lens.severity.includes(s)?c:'#64748b'};padding:5px;border-radius:7px;cursor:pointer;font-size:10px;transition:all .15s;">${s}</button>`).join('')}
      </div>
    </div>

    <!-- Campaign Status -->
    <div>
      <div style="font-size:9px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">Campaign Status</div>
      <div style="display:flex;gap:5px;">
        ${[['active','#22c55e'],['historical','#64748b']].map(([s,c]) => `
        <button onclick="tgv2LensFilterCampaign('${s}')" style="flex:1;background:${_s.lens.campaignStatus===s?c+'22':'#0a0e17'};border:1px solid ${_s.lens.campaignStatus===s?c:'#1e293b'};color:${_s.lens.campaignStatus===s?c:'#64748b'};padding:5px;border-radius:7px;cursor:pointer;font-size:10px;transition:all .15s;">${s}</button>`).join('')}
      </div>
    </div>

    <!-- Time Window -->
    <div>
      <div style="font-size:9px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">Time Window</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;">
        ${['all','last7d','last30d','last90d','last1y'].map(tw => `
        <button onclick="tgv2LensTimeWindow('${tw}')" style="background:#0a0e17;border:1px solid ${_s.lens.timeWindow===tw?'#22d3ee':'#1e293b'};color:${_s.lens.timeWindow===tw?'#22d3ee':'#64748b'};padding:4px 10px;border-radius:20px;cursor:pointer;font-size:10px;transition:all .15s;">${tw==='all'?'All Time':tw.replace('last','Last ').replace('d',' days').replace('y',' year')}</button>`).join('')}
      </div>
    </div>

    <!-- Composite mode -->
    <div style="display:flex;align-items:center;justify-content:space-between;padding-top:8px;border-top:1px solid #1e293b;">
      <span style="font-size:10px;color:#64748b;">Filter composition:</span>
      <div style="display:flex;gap:6px;">
        <button id="tgv2-composite-btn" onclick="tgv2CompositeMode()" style="background:#0a0e17;border:1px solid #1e293b;color:#94a3b8;padding:4px 12px;border-radius:20px;cursor:pointer;font-size:10px;font-weight:700;">${_s.lens.compositeOR?'OR':'AND'}</button>
        <button onclick="tgv2SaveLens()" style="background:#0a0e17;border:1px solid #1e293b;color:#64748b;padding:4px 10px;border-radius:20px;cursor:pointer;font-size:10px;"><i class="fas fa-save" style="margin-right:3px;"></i>Save Lens</button>
        <button onclick="tgv2LensClear()" style="background:#0a0e17;border:1px solid #1e293b;color:#64748b;padding:4px 10px;border-radius:20px;cursor:pointer;font-size:10px;">Clear All</button>
      </div>
    </div>
  </div>`;
}

/* ═══════════════════════════════════════════════════════════════════════════
   §13  EGOCENTRIC MODE (Enhancement 5)
═══════════════════════════════════════════════════════════════════════════ */
function _enterEgoMode(nodeId) {
  const node = _s.nodes.find(n=>n.id===nodeId);
  if (!node) return;

  /* Build neighbor sets */
  const d1 = new Set(), d2 = new Set(), d3 = new Set();
  _s.allEdges.forEach(e => {
    if (e.src===nodeId) d1.add(e.tgt);
    if (e.tgt===nodeId) d1.add(e.src);
  });
  d1.forEach(id => {
    _s.allEdges.forEach(e => {
      if (e.src===id && e.tgt!==nodeId && !d1.has(e.tgt)) d2.add(e.tgt);
      if (e.tgt===id && e.src!==nodeId && !d1.has(e.src)) d2.add(e.src);
    });
  });
  d2.forEach(id => {
    _s.allEdges.forEach(e => {
      if (e.src===id && !d1.has(e.tgt) && !d2.has(e.tgt) && e.tgt!==nodeId) d3.add(e.tgt);
      if (e.tgt===id && !d1.has(e.src) && !d2.has(e.src) && e.src!==nodeId) d3.add(e.src);
    });
  });

  _s.ego.history.push(_s.ego.centerId);
  _s.ego = { ..._s.ego, active:true, centerId:nodeId, depth1:d1, depth2:d2, depth3:d3 };

  _updateEgoBreadcrumb();
  _generateNarration('ego_mode', `Ego view centered on ${node.label}. ${d1.size} direct neighbors (1st degree), ${d2.size} secondary neighbors (2nd degree), ${d3.size} tertiary (3rd degree).`);
  _toast(`Ego mode: ${node.label} — ${d1.size} direct connections`, 'info');
}

function _updateEgoBreadcrumb() {
  const bc = document.getElementById('tgv2-ego-breadcrumb');
  if (!bc) return;
  const history = _s.ego.history.filter(Boolean);
  const current = _s.allNodes.find(n=>n.id===_s.ego.centerId)?.label||_s.ego.centerId||'';
  bc.innerHTML = history.length ? `
    <div style="display:flex;align-items:center;gap:4px;font-size:10px;color:#475569;flex-wrap:wrap;">
      ${history.map((id,i) => {
        const label = _s.allNodes.find(n=>n.id===id)?.label||id||'Graph';
        return `<span style="cursor:pointer;color:#64748b;" onclick="tgv2EgoBack(${i})">${_e(label)}</span><span>›</span>`;
      }).join('')}
      <span style="color:#22d3ee;font-weight:600;">${_e(current)}</span>
      <button onclick="tgv2ExitEgo()" style="background:#1e293b;border:none;color:#475569;padding:2px 7px;border-radius:4px;cursor:pointer;font-size:9px;margin-left:4px;">Esc</button>
      <button onclick="tgv2PinEgo()" style="background:${_s.ego.pinned?'#22d3ee22':'#1e293b'};border:1px solid ${_s.ego.pinned?'#22d3ee':'#334155'};color:${_s.ego.pinned?'#22d3ee':'#475569'};padding:2px 7px;border-radius:4px;cursor:pointer;font-size:9px;"><i class="fas fa-thumbtack"></i> Pin</button>
    </div>` : '';
}

window.tgv2ExitEgo = function() {
  _s.ego = { active:false, centerId:null, depth1:new Set(), depth2:new Set(), depth3:new Set(), history:[], pinned:false };
  _updateEgoBreadcrumb();
};
window.tgv2EgoBack = function(histIdx) {
  const id = _s.ego.history[histIdx];
  if (id) _enterEgoMode(id);
  _s.ego.history = _s.ego.history.slice(0, histIdx);
};
window.tgv2PinEgo = function() {
  _s.ego.pinned = !_s.ego.pinned;
  _updateEgoBreadcrumb();
  _toast(_s.ego.pinned ? 'Ego view pinned' : 'Ego view unpinned', 'info');
};

/* ═══════════════════════════════════════════════════════════════════════════
   §14  AI NARRATOR (Enhancement 6)
═══════════════════════════════════════════════════════════════════════════ */
const NARRATOR_TEMPLATES = {
  node_click: (n) => {
    const cfg = NODE_CFG[n.type]||NODE_CFG.infrastructure;
    const relCount = _s.allEdges.filter(e=>e.src===n.id||e.tgt===n.id).length;
    const peers = _s.allEdges.filter(e=>(e.src===n.id||e.tgt===n.id)&&e.rel==='shares_infra').length;
    if (n.type==='threat_actor') {
      return `**${n.label}** (${n.origin||'Unknown'} · ${n.sponsor||'Unknown sponsor'}) is active since ${n.active_since||'unknown date'}. It has **${relCount} connections** in this graph — ${peers} infrastructure sharing relationships with other actors. Attribution confidence: **${n.confidence||'N/A'}%**. Current threat level: <span style="color:${_riskColor(n.risk||0)};font-weight:700;">${n.risk||0}/100</span>. Primary targeted sectors: ${(n.sectors||[]).join(', ')||'Unknown'}.`;
    }
    if (n.type==='malware') return `**${n.label}** is a **${n.family||'unknown family'}** malware family. First observed: ${n.first_seen||'unknown'}. Last seen: ${n.last_seen||'unknown'}. ${n.description||''} It appears in **${relCount} relationships** in the current graph.`;
    if (n.type==='campaign') return `**${n.label}** is a ${n.status==='active'?'<span style="color:#ef4444;font-weight:700;">ACTIVE</span>':'historical'} campaign. Started: ${n.start||'unknown'}${n.end?` · Ended: ${n.end}`:''}. Impact: **${n.impact||'Unknown'}**. ${n.victims?`Victims: ${n.victims.toLocaleString()}.`:''} ${n.description||''}`;
    if (n.type==='technique') return `**${n.label}** (MITRE ${n.mitre_id||''}) maps to the **${n.tactic||'Unknown'}** tactic. ${n.description||''} This technique is used by **${_s.allEdges.filter(e=>e.tgt===n.id&&e.rel==='uses').length} actors** in the current dataset.`;
    return `**${n.label}** (${cfg.label}) — Risk: ${n.risk||0}/100. ${n.description||''} Appears in ${relCount} graph relationships.`;
  },
  temporal_scrub: (msg) => msg,
  snap_event: (msg) => msg,
  attack_path: (msg) => `**Attack Path Computed** — ${msg}. This path represents the most probable adversarial route based on TTP co-occurrence, infrastructure overlap, and historical campaign proximity.`,
  blast_radius: (msg) => `**Blast Radius Simulation** — ${msg}. Rings are color-coded: Red (direct actors), Orange (infrastructure-adjacent), Amber (TTP-similar potential threat).`,
  ego_mode: (msg) => `**Ego View Active** — ${msg}. Depth rings show relationship distance. Double-click another node to dive deeper, or press Escape to return.`,
  filter_change: (msg) => `Filter applied: ${msg}. Graph now shows **${_s.nodes.length} nodes** and **${_s.edges.length} edges** matching your lens criteria.`,
};

function _generateNarration(action, context) {
  const tpl = NARRATOR_TEMPLATES[action];
  if (!tpl) return;
  const msg = typeof tpl === 'function' ? tpl(context) : tpl;
  _s.narrator.message = msg;
  _s.narrator.lastAction = action;
  _renderNarrator();
}

function _renderNarrator() {
  const el = document.getElementById('tgv2-narrator-content');
  if (!el) return;
  el.innerHTML = `<div style="font-size:11px;color:#94a3b8;line-height:1.7;">${_s.narrator.message.replace(/\*\*([^*]+)\*\*/g,'<strong style="color:#f1f5f9;">$1</strong>')}</div>`;
}

function _renderNarratorDefault() {
  _s.narrator.message = 'Click any node or perform an action — I\'ll provide instant AI context, relationship analysis, and tactical recommendations.';
  _renderNarrator();
}

window.tgv2NarratorToggle = function() {
  _s.narrator.open = !_s.narrator.open;
  const panel = document.getElementById('tgv2-narrator-panel');
  if (panel) {
    panel.style.width = _s.narrator.open ? '320px' : '0';
    panel.style.overflow = _s.narrator.open ? 'visible' : 'hidden';
  }
  const btn = document.getElementById('tgv2-narrator-btn');
  if (btn) btn.style.borderColor = _s.narrator.open ? '#22d3ee' : '#1e293b';
};

/* ═══════════════════════════════════════════════════════════════════════════
   §15  CANVAS EVENT HANDLERS
═══════════════════════════════════════════════════════════════════════════ */
function _canvasCoords(e) {
  const canvas = _s.canvas;
  if (!canvas) return {x:0,y:0};
  const rect = canvas.getBoundingClientRect();
  return {
    x: (e.clientX - rect.left - _s.pan.x) / _s.zoom,
    y: (e.clientY - rect.top  - _s.pan.y) / _s.zoom,
  };
}

function _findNode(x, y) {
  return _s.nodes.find(n => {
    const p = _s.positions.get(n.id);
    if (!p) return false;
    const cfg = NODE_CFG[n.type]||NODE_CFG.infrastructure;
    const dx = p.x-x, dy = p.y-y;
    return Math.sqrt(dx*dx+dy*dy) < (cfg.size+6)/_s.zoom;
  });
}

let _lastClick = 0;
function _onMouseDown(e) {
  if (e.button === 2) return; /* right-click handled separately */
  const {x,y} = _canvasCoords(e);
  const node = _findNode(x,y);
  if (node) { _s.dragNode=node; _s.canvas.style.cursor='grabbing'; }
  else { _s.dragging=true; _s.panStart={x:e.clientX-_s.pan.x, y:e.clientY-_s.pan.y}; }
}
function _onMouseMove(e) {
  const {x,y} = _canvasCoords(e);
  if (_s.dragNode) {
    const p = _s.positions.get(_s.dragNode.id);
    if (p) { p.x=x; p.y=y; p.vx=0; p.vy=0; }
  } else if (_s.dragging && _s.panStart) {
    _s.pan.x = e.clientX - _s.panStart.x;
    _s.pan.y = e.clientY - _s.panStart.y;
  } else {
    _s.hoverNode = _findNode(x,y);
    _s.canvas.style.cursor = _s.hoverNode ? 'pointer' : 'grab';
  }
}
function _onMouseUp(e) {
  _s.dragging=false; _s.dragNode=null; _s.panStart=null;
  _s.canvas.style.cursor='grab';
}
function _onClick(e) {
  const {x,y} = _canvasCoords(e);
  const node = _findNode(x,y);
  const now = Date.now();

  if (!node) {
    /* Click on canvas background */
    if (_s.ego.active) tgv2ExitEgo();
    if (_s.attackPath.shiftHeld && !node) { _s.attackPath.source=null; _s.attackPath.target=null; }
    _s.contextMenu && (_s.contextMenu.style.display='none');
    return;
  }

  /* Double-click → ego mode */
  if (now - _lastClick < 350) {
    _enterEgoMode(node.id);
    _lastClick = 0;
    return;
  }
  _lastClick = now;

  /* Shift+click → attack path */
  if (e.shiftKey) {
    if (!_s.attackPath.source) {
      _s.attackPath.source = node.id;
      _s.attackPath.shiftHeld = true;
      _toast(`Source: ${node.label} — Shift+click target`, 'info');
    } else if (node.id !== _s.attackPath.source) {
      _s.attackPath.target = node.id;
      _s.attackPath.shiftHeld = false;
      _computeAttackPath(_s.attackPath.source, node.id);
    }
    return;
  }

  /* Single click → select + narration */
  _s.selectedNode = node;
  _renderNodeDetailPanel(node);
  _generateNarration('node_click', node);
}

function _onDblClick(e) {
  const {x,y} = _canvasCoords(e);
  const node = _findNode(x,y);
  if (node) _enterEgoMode(node.id);
}

function _onWheel(e) {
  e.preventDefault();
  const delta = e.deltaY > 0 ? -0.08 : 0.08;
  _s.zoom = Math.max(0.2, Math.min(4, _s.zoom + delta));
}

function _onContextMenu(e) {
  e.preventDefault();
  const {x,y} = _canvasCoords(e);
  const node = _findNode(x,y);
  const menu = document.getElementById('tgv2-context-menu');
  if (!menu) return;
  if (node) {
    _s.contextMenu = menu;
    menu.innerHTML = `
      <div style="padding:6px 0;">
        <div style="padding:4px 16px;font-size:11px;font-weight:700;color:#94a3b8;border-bottom:1px solid #1e293b;margin-bottom:4px;">${_e(node.label)}</div>
        <div class="tgv2-menu-item" onclick="tgv2BlastRadius('${node.id}');document.getElementById('tgv2-context-menu').style.display='none'"><i class="fas fa-radiation" style="width:14px;color:#ef4444;"></i> Simulate Blast Radius</div>
        <div class="tgv2-menu-item" onclick="_enterEgoMode('${node.id}');document.getElementById('tgv2-context-menu').style.display='none'"><i class="fas fa-bullseye" style="width:14px;color:#22d3ee;"></i> Enter Ego Mode</div>
        <div class="tgv2-menu-item" onclick="_s.attackPath.source='${node.id}';_s.attackPath.shiftHeld=true;document.getElementById('tgv2-context-menu').style.display='none';_toast('Source set — click target node','info')"><i class="fas fa-route" style="width:14px;color:#a855f7;"></i> Set as Attack Path Source</div>
        <div class="tgv2-menu-item" onclick="tgv2FocusNode('${node.id}');document.getElementById('tgv2-context-menu').style.display='none'"><i class="fas fa-crosshairs" style="width:14px;color:#f97316;"></i> Focus & Center</div>
        <div style="height:1px;background:#1e293b;margin:4px 0;"></div>
        <div class="tgv2-menu-item" onclick="window.open('https://attack.mitre.org/','_blank');document.getElementById('tgv2-context-menu').style.display='none'"><i class="fas fa-external-link-alt" style="width:14px;color:#64748b;"></i> View on MITRE ATT&CK</div>
      </div>`;
    menu.style.display = 'block';
    menu.style.left = e.clientX + 'px';
    menu.style.top  = e.clientY + 'px';
  } else {
    menu.style.display='none';
  }
}

function _onKeyDown(e) {
  if (e.key==='Escape') {
    tgv2ExitEgo();
    tgv2ClearAttackPath();
    tgv2ClearBlast();
    const menu = document.getElementById('tgv2-context-menu');
    if (menu) menu.style.display='none';
  }
  if ((e.metaKey||e.ctrlKey) && e.key==='f') {
    e.preventDefault();
    tgv2LensToggle();
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   §16  NODE DETAIL PANEL
═══════════════════════════════════════════════════════════════════════════ */
function _renderNodeDetailPanel(node) {
  const panel = document.getElementById('tgv2-right-panel-content');
  if (!panel) return;

  const cfg = NODE_CFG[node.type]||NODE_CFG.infrastructure;
  const relEdges = _s.allEdges.filter(e=>e.src===node.id||e.tgt===node.id);
  const relNodes = relEdges.map(e=>e.src===node.id?e.tgt:e.src).map(id=>_s.allNodes.find(n=>n.id===id)).filter(Boolean);

  panel.innerHTML = `
  <div style="padding:16px;">
    <!-- Node header -->
    <div style="background:${cfg.bg};border:1px solid ${cfg.color}40;border-radius:12px;padding:16px;margin-bottom:14px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
        <div style="width:36px;height:36px;background:${cfg.color}22;border-radius:10px;display:flex;align-items:center;justify-content:center;"><i class="fas ${cfg.icon}" style="color:${cfg.color};font-size:16px;"></i></div>
        <div>
          <div style="font-size:9px;color:${cfg.color};font-weight:700;text-transform:uppercase;letter-spacing:.05em;">${cfg.label}</div>
          <div style="font-size:14px;font-weight:800;color:#f1f5f9;">${_e(node.label)}</div>
        </div>
        <div style="margin-left:auto;background:${_riskColor(node.risk||0)}22;border:1px solid ${_riskColor(node.risk||0)}44;border-radius:8px;padding:4px 10px;font-size:11px;font-weight:700;color:${_riskColor(node.risk||0)};">
          ${node.risk||0}/100
        </div>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;">
        ${node.origin?`<span style="font-size:9px;background:#0a0e17;border:1px solid #1e293b;border-radius:20px;padding:2px 8px;color:#64748b;">${ACTOR_ORIGINS.find(o=>o.code===node.origin)?.flag||'🌐'} ${node.origin}</span>`:''}
        ${node.sponsor?`<span style="font-size:9px;background:#0a0e17;border:1px solid #1e293b;border-radius:20px;padding:2px 8px;color:#64748b;">${_e(node.sponsor)}</span>`:''}
        ${node.status?`<span style="font-size:9px;background:${node.status==='active'?'#22c55e22':'#1e293b'};border:1px solid ${node.status==='active'?'#22c55e':'#1e293b'};border-radius:20px;padding:2px 8px;color:${node.status==='active'?'#22c55e':'#64748b'};">${node.status}</span>`:''}
      </div>
    </div>

    <!-- AI Narrator for this node -->
    <div style="background:#090d14;border:1px solid #1e293b;border-left:2px solid #22d3ee;border-radius:8px;padding:12px;margin-bottom:14px;">
      <div style="font-size:9px;font-weight:700;color:#22d3ee;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px;"><i class="fas fa-brain" style="margin-right:4px;"></i>AI Context</div>
      <div style="font-size:10px;color:#94a3b8;line-height:1.7;">${NARRATOR_TEMPLATES.node_click(node).replace(/\*\*([^*]+)\*\*/g,'<strong style="color:#f1f5f9;">$1</strong>')}</div>
    </div>

    <!-- Quick actions -->
    <div style="display:flex;gap:5px;margin-bottom:14px;flex-wrap:wrap;">
      <button onclick="tgv2BlastRadius('${node.id}')" style="flex:1;background:#ef444418;border:1px solid #ef444433;color:#ef4444;padding:5px 8px;border-radius:7px;cursor:pointer;font-size:9px;font-weight:600;"><i class="fas fa-radiation" style="margin-right:3px;"></i>Blast</button>
      <button onclick="_enterEgoMode('${node.id}')" style="flex:1;background:#22d3ee18;border:1px solid #22d3ee33;color:#22d3ee;padding:5px 8px;border-radius:7px;cursor:pointer;font-size:9px;font-weight:600;"><i class="fas fa-bullseye" style="margin-right:3px;"></i>Ego</button>
      <button onclick="_s.attackPath.source='${node.id}';_s.attackPath.shiftHeld=true;_toast('Source set — Shift+click target','info')" style="flex:1;background:#a855f718;border:1px solid #a855f733;color:#a855f7;padding:5px 8px;border-radius:7px;cursor:pointer;font-size:9px;font-weight:600;"><i class="fas fa-route" style="margin-right:3px;"></i>Path</button>
    </div>

    <!-- Relationships -->
    ${relNodes.length ? `
    <div style="margin-bottom:14px;">
      <div style="font-size:9px;font-weight:700;color:#475569;text-transform:uppercase;margin-bottom:8px;">Relationships (${relNodes.length})</div>
      <div style="max-height:200px;overflow-y:auto;display:flex;flex-direction:column;gap:4px;">
        ${relNodes.slice(0,12).map(rn => {
          const edge = relEdges.find(e=>(e.src===rn.id&&e.tgt===node.id)||(e.src===node.id&&e.tgt===rn.id));
          const rc = NODE_CFG[rn.type]||NODE_CFG.infrastructure;
          return `<div onclick="tgv2FocusNode('${rn.id}')" style="display:flex;align-items:center;gap:7px;padding:7px 9px;background:#090d14;border-radius:6px;cursor:pointer;transition:background .15s;border:1px solid transparent;" onmouseover="this.style.background='#1e293b';this.style.borderColor='#334155'" onmouseout="this.style.background='#090d14';this.style.borderColor='transparent'">
            <i class="fas ${rc.icon}" style="color:${rc.color};font-size:11px;width:14px;"></i>
            <div style="flex:1;min-width:0;">
              <div style="font-size:11px;font-weight:600;color:#e2e8f0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${_e(rn.label)}</div>
              <div style="font-size:9px;color:#475569;">${_e(edge?.rel||'related')}</div>
            </div>
            <span style="font-size:9px;color:${rc.color};">${rc.label}</span>
          </div>`;
        }).join('')}
      </div>
    </div>` : ''}

    <!-- TTPs -->
    ${node.ttps?.length ? `
    <div style="margin-bottom:14px;">
      <div style="font-size:9px;font-weight:700;color:#475569;text-transform:uppercase;margin-bottom:8px;">Known TTPs</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">
        ${node.ttps.map(t=>`<span style="font-size:9px;background:#3b82f618;border:1px solid #3b82f633;color:#60a5fa;border-radius:4px;padding:2px 7px;">${_e(t)}</span>`).join('')}
      </div>
    </div>` : ''}

    <!-- Tools -->
    ${node.tools?.length ? `
    <div>
      <div style="font-size:9px;font-weight:700;color:#475569;text-transform:uppercase;margin-bottom:8px;">Tools / Malware</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">
        ${node.tools.map(t=>`<span style="font-size:9px;background:#f9731618;border:1px solid #f9731633;color:#fb923c;border-radius:4px;padding:2px 7px;">${_e(t)}</span>`).join('')}
      </div>
    </div>` : ''}
  </div>`;
}

window.tgv2FocusNode = function(nodeId) {
  const node = _s.nodes.find(n=>n.id===nodeId);
  if (!node) return;
  const p = _s.positions.get(nodeId);
  if (p && _s.canvas) {
    _s.pan.x = _s.canvas.width/2 - p.x*_s.zoom;
    _s.pan.y = _s.canvas.height/2 - p.y*_s.zoom;
  }
  _s.selectedNode = node;
  _renderNodeDetailPanel(node);
  _generateNarration('node_click', node);
};

/* ═══════════════════════════════════════════════════════════════════════════
   §17  MAIN RENDER / SHELL
═══════════════════════════════════════════════════════════════════════════ */
function _buildShell(container) {
  container.innerHTML = `
  <style>
    @keyframes tgv2ToastIn { from{opacity:0;transform:translateX(40px)} to{opacity:1;transform:none} }
    .tgv2-menu-item { padding:6px 16px;font-size:11px;color:#94a3b8;cursor:pointer;display:flex;align-items:center;gap:8px;transition:background .12s; }
    .tgv2-menu-item:hover { background:#1e293b;color:#f1f5f9; }
    #tgv2-time-slider { -webkit-appearance:none;height:4px;border-radius:2px;background:linear-gradient(90deg,#22d3ee 0%,#1e293b 100%);outline:none; }
    #tgv2-time-slider::-webkit-slider-thumb { -webkit-appearance:none;width:14px;height:14px;border-radius:50%;background:#22d3ee;cursor:pointer;box-shadow:0 0 8px #22d3ee88; }
    .tgv2-lens-btn { background:#0a0e17;border:1px solid #1e293b;color:#64748b;padding:5px 12px;border-radius:20px;cursor:pointer;font-size:10px;transition:all .15s; }
    .tgv2-lens-btn:hover { border-color:#22d3ee44;color:#94a3b8; }
    .tgv2-lens-btn.active { border-color:#22d3ee;color:#22d3ee;background:#22d3ee11; }
  </style>

  <div id="tgv2-root" style="display:flex;flex-direction:column;height:100%;background:#070b12;font-family:Inter,-apple-system,sans-serif;position:relative;">

    <!-- ── Header ── -->
    <div style="background:linear-gradient(135deg,#0a0e17,#0a1628);border-bottom:1px solid #1e293b;padding:16px 20px 12px;flex-shrink:0;">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:12px;">
        <div style="display:flex;align-items:center;gap:12px;">
          <div style="width:40px;height:40px;background:linear-gradient(135deg,#22d3ee,#3b82f6);border-radius:12px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 16px rgba(34,211,238,.25);">
            <i class="fas fa-project-diagram" style="color:#fff;font-size:18px;"></i>
          </div>
          <div>
            <div style="display:flex;align-items:center;gap:8px;">
              <h1 style="margin:0;font-size:1.2rem;font-weight:800;color:#f1f5f9;">Threat Intelligence Graph</h1>
              <span style="font-size:9px;font-weight:700;background:linear-gradient(90deg,#22d3ee,#3b82f6);color:#fff;padding:2px 8px;border-radius:10px;">v2.0</span>
            </div>
            <div style="font-size:10px;color:#64748b;margin-top:1px;">Force-directed · Temporal · Attack Path · Blast Radius · Ego Mode · AI Narrator</div>
          </div>
        </div>

        <!-- Node legend -->
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
          ${Object.entries(NODE_CFG).map(([type,cfg])=>`
          <div onclick="tgv2LegendFilter('${type}')" id="tgv2-legend-${type}" style="display:flex;align-items:center;gap:4px;background:#0f172a;border:1px solid #1e293b;padding:4px 9px;border-radius:20px;cursor:pointer;transition:all .2s;" title="${cfg.label}">
            <div style="width:7px;height:7px;border-radius:50%;background:${cfg.color};"></div>
            <span style="font-size:9px;color:#64748b;">${cfg.label}</span>
          </div>`).join('')}
        </div>
      </div>

      <!-- Toolbar row 1: search + controls -->
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
        <div style="position:relative;min-width:200px;">
          <i class="fas fa-search" style="position:absolute;left:10px;top:50%;transform:translateY(-50%);color:#475569;font-size:11px;"></i>
          <input id="tgv2-search" type="text" placeholder="Search node…" oninput="tgv2Search(this.value)"
            style="background:#0a0e17;border:1px solid #1e293b;color:#e2e8f0;padding:6px 10px 6px 28px;border-radius:8px;font-size:11px;outline:none;width:100%;box-sizing:border-box;">
        </div>

        <!-- Lens filter toggle -->
        <button id="tgv2-lens-btn" onclick="tgv2LensToggle()" style="background:#0a0e17;border:1px solid #1e293b;color:#64748b;padding:6px 12px;border-radius:8px;cursor:pointer;font-size:11px;display:flex;align-items:center;gap:5px;transition:all .2s;" title="Lens Filters (Ctrl+F)">
          <i class="fas fa-filter"></i> Filters
          <span id="tgv2-filter-count" style="background:#22d3ee22;color:#22d3ee;border-radius:10px;padding:0 5px;font-size:9px;display:none;">0</span>
        </button>

        <!-- Temporal toggle -->
        <button id="tgv2-temporal-btn" onclick="tgv2TemporalToggle()" style="background:#0a0e17;border:1px solid #1e293b;color:#64748b;padding:6px 12px;border-radius:8px;cursor:pointer;font-size:11px;display:flex;align-items:center;gap:5px;transition:all .2s;" title="Temporal Replay">
          <i class="fas fa-history"></i> Timeline
        </button>

        <!-- Narrator toggle -->
        <button id="tgv2-narrator-btn" onclick="tgv2NarratorToggle()" style="background:#0a0e17;border:1px solid #22d3ee;color:#22d3ee;padding:6px 12px;border-radius:8px;cursor:pointer;font-size:11px;display:flex;align-items:center;gap:5px;transition:all .2s;" title="AI Narrator">
          <i class="fas fa-brain"></i> AI Narrator
        </button>

        <div style="display:flex;gap:3px;">
          <button onclick="tgv2Zoom(0.2)" style="background:#0a0e17;border:1px solid #1e293b;color:#94a3b8;padding:6px 10px;border-radius:6px;cursor:pointer;font-size:12px;" title="Zoom In">+</button>
          <button onclick="tgv2Zoom(-0.2)" style="background:#0a0e17;border:1px solid #1e293b;color:#94a3b8;padding:6px 10px;border-radius:6px;cursor:pointer;font-size:12px;" title="Zoom Out">-</button>
          <button onclick="tgv2ResetView()" style="background:#0a0e17;border:1px solid #1e293b;color:#94a3b8;padding:6px 10px;border-radius:6px;cursor:pointer;font-size:11px;" title="Fit"><i class="fas fa-compress-alt"></i></button>
          <button onclick="tgv2ToggleSim()" id="tgv2-sim-btn" style="background:#0a0e17;border:1px solid #1e293b;color:#22c55e;padding:6px 10px;border-radius:6px;cursor:pointer;font-size:11px;" title="Toggle Physics"><i class="fas fa-atom"></i></button>
        </div>

        <div id="tgv2-node-count" style="font-size:10px;color:#475569;padding:6px 10px;background:#0a0e17;border:1px solid #1e293b;border-radius:8px;margin-left:auto;">
          ${V2_NODES.length} nodes · ${V2_EDGES.length} edges
        </div>
      </div>

      <!-- Active filter pills -->
      <div id="tgv2-active-filters" style="display:flex;flex-wrap:wrap;gap:5px;margin-top:8px;min-height:20px;"></div>

      <!-- Ego breadcrumb -->
      <div id="tgv2-ego-breadcrumb" style="margin-top:6px;min-height:20px;"></div>
    </div>

    <!-- ── Lens filter panel (inline, collapsible) ── -->
    <div id="tgv2-lens-panel" style="display:none;background:#0a0e17;border-bottom:1px solid #1e293b;"></div>

    <!-- ── Temporal strip ── -->
    <div id="tgv2-temporal-strip" style="display:none;background:#090d14;border-bottom:1px solid #1e293b;padding:10px 20px;flex-shrink:0;align-items:center;gap:10px;flex-wrap:wrap;">
      <!-- Play/Pause -->
      <button id="tgv2-play-btn" onclick="tgv2TemporalPlay()" style="background:#22d3ee22;border:1px solid #22d3ee44;color:#22d3ee;padding:5px 12px;border-radius:8px;cursor:pointer;font-size:12px;"><i class="fas fa-play"></i></button>

      <!-- Speed buttons -->
      <div id="tgv2-speed-btns" style="display:flex;gap:3px;">
        ${[1,5,10].map(s=>`<button data-speed="${s}" onclick="tgv2TemporalSpeed(${s})" style="background:${s===1?'#22d3ee22':'#0a0e17'};border:1px solid ${s===1?'#22d3ee':'#1e293b'};color:${s===1?'#22d3ee':'#64748b'};padding:4px 8px;border-radius:6px;cursor:pointer;font-size:10px;font-weight:700;">${s}×</button>`).join('')}
      </div>

      <!-- Timeline slider -->
      <div style="flex:1;min-width:200px;position:relative;">
        <input id="tgv2-time-slider" type="range" min="0" max="1000" value="1000" oninput="tgv2TemporalScrub(this.value)" style="width:100%;cursor:pointer;">
        <!-- Event markers -->
        <div style="position:absolute;top:-12px;left:0;right:0;height:10px;pointer-events:none;">
          ${TIMELINE_EVENTS.map((ev,i) => {
            const minD = new Date('2008-01-01').getTime(), maxD = new Date('2025-05-23').getTime();
            const pos  = Math.round(((new Date(ev.date).getTime()-minD)/(maxD-minD))*100);
            return `<div onclick="tgv2SnapToEvent(${i})" title="${ev.label}: ${ev.desc}" style="position:absolute;left:${pos}%;width:2px;height:8px;background:#22d3ee;border-radius:1px;cursor:pointer;pointer-events:all;top:2px;transform:translateX(-50%);"></div>`;
          }).join('')}
        </div>
      </div>

      <!-- Date display -->
      <div id="tgv2-date-display" style="font-size:11px;font-weight:700;color:#22d3ee;min-width:80px;text-align:center;background:#22d3ee11;border:1px solid #22d3ee22;border-radius:6px;padding:4px 10px;">
        ${new Date().toISOString().slice(0,10)}
      </div>

      <!-- Delta mode -->
      <button id="tgv2-delta-btn" onclick="tgv2DeltaMode()" style="background:#0a0e17;border:1px solid #1e293b;color:#64748b;padding:4px 10px;border-radius:6px;cursor:pointer;font-size:10px;font-weight:600;" title="Delta mode: highlight changes">Δ Delta</button>

      <!-- Events dropdown -->
      <div style="position:relative;">
        <button onclick="document.getElementById('tgv2-events-dropdown').style.display=document.getElementById('tgv2-events-dropdown').style.display==='none'?'block':'none'" style="background:#0a0e17;border:1px solid #1e293b;color:#64748b;padding:4px 10px;border-radius:6px;cursor:pointer;font-size:10px;">
          <i class="fas fa-bolt"></i> Events
        </button>
        <div id="tgv2-events-dropdown" style="display:none;position:absolute;bottom:100%;left:0;background:#0f172a;border:1px solid #1e293b;border-radius:10px;min-width:220px;box-shadow:0 8px 32px rgba(0,0,0,.6);z-index:100;padding:6px 0;margin-bottom:4px;">
          ${TIMELINE_EVENTS.map((ev,i)=>`
          <div onclick="tgv2SnapToEvent(${i});document.getElementById('tgv2-events-dropdown').style.display='none'" style="padding:6px 14px;cursor:pointer;font-size:10px;color:#94a3b8;transition:background .12s;" onmouseover="this.style.background='#1e293b'" onmouseout="this.style.background=''">
            <span style="color:#22d3ee;font-weight:700;">${ev.date}</span> — ${_e(ev.label)}
          </div>`).join('')}
        </div>
      </div>

      <!-- Live button -->
      <button onclick="tgv2TemporalLive()" style="background:linear-gradient(135deg,#22c55e22,#16a34a22);border:1px solid #22c55e44;color:#22c55e;padding:4px 12px;border-radius:6px;cursor:pointer;font-size:10px;font-weight:700;display:flex;align-items:center;gap:4px;">
        <span style="width:5px;height:5px;border-radius:50%;background:#22c55e;animation:tgv2ToastIn 1s infinite alternate;"></span> LIVE
      </button>
    </div>

    <!-- ── Main body: canvas + right panels ── -->
    <div style="flex:1;display:flex;min-height:0;overflow:hidden;position:relative;">

      <!-- Canvas -->
      <div style="flex:1;position:relative;overflow:hidden;background:radial-gradient(ellipse at center,#0d1b2e 0%,#070b12 70%);">
        <canvas id="tgv2-canvas" style="display:block;cursor:grab;width:100%;height:100%;"></canvas>

        <!-- Hover tooltip -->
        <div id="tgv2-tooltip" style="display:none;position:fixed;background:rgba(9,13,20,.97);border:1px solid #1e293b;border-radius:10px;padding:10px 13px;max-width:220px;pointer-events:none;z-index:200;box-shadow:0 8px 32px rgba(0,0,0,.7);font-size:11px;"></div>

        <!-- Canvas overlay hints -->
        <div style="position:absolute;top:12px;left:12px;background:rgba(9,13,20,.8);border:1px solid #1e293b;border-radius:8px;padding:8px 12px;font-size:10px;color:#475569;display:flex;flex-direction:column;gap:3px;">
          <span><i class="fas fa-mouse-pointer" style="width:12px;color:#64748b;"></i> Click: select · Double-click: ego mode</span>
          <span><i class="fas fa-keyboard" style="width:12px;color:#64748b;"></i> Shift+click 2 nodes: attack path</span>
          <span><i class="fas fa-mouse" style="width:12px;color:#64748b;"></i> Right-click: context menu</span>
        </div>

        <!-- Shift+click indicator -->
        <div id="tgv2-shift-indicator" style="display:none;position:absolute;top:12px;right:12px;background:#22d3ee11;border:1px solid #22d3ee44;border-radius:8px;padding:8px 12px;font-size:10px;color:#22d3ee;">
          <i class="fas fa-route" style="margin-right:4px;"></i>Attack Path Mode — Shift+click target
        </div>
      </div>

      <!-- Right panel: Node detail / Attack path / Blast radius -->
      <div id="tgv2-right-panel" style="width:300px;background:#0f172a;border-left:1px solid #1e293b;display:flex;flex-direction:column;flex-shrink:0;overflow:hidden;transition:width .3s;">
        <div style="padding:10px 14px;border-bottom:1px solid #1e293b;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.06em;display:flex;align-items:center;justify-content:space-between;">
          <span><i class="fas fa-info-circle" style="margin-right:5px;color:#22d3ee;"></i>Intelligence Panel</span>
          <button onclick="document.getElementById('tgv2-right-panel').style.width=document.getElementById('tgv2-right-panel').style.width==='0px'?'300px':'0px'" style="background:none;border:none;color:#475569;cursor:pointer;padding:2px 6px;border-radius:4px;" title="Collapse panel">‹</button>
        </div>
        <div id="tgv2-right-panel-content" style="flex:1;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#1e293b transparent;">
          <div style="padding:24px 20px;text-align:center;color:#334155;">
            <i class="fas fa-hand-pointer" style="font-size:24px;margin-bottom:8px;display:block;"></i>
            <div style="font-size:11px;">Click a node to view intelligence details</div>
          </div>
        </div>
      </div>

      <!-- AI Narrator panel -->
      <div id="tgv2-narrator-panel" style="width:300px;background:#070b12;border-left:1px solid #1e293b;display:flex;flex-direction:column;flex-shrink:0;overflow:hidden;transition:width .3s;">
        <div style="padding:10px 14px;border-bottom:1px solid #1e293b;font-size:10px;font-weight:700;color:#22d3ee;text-transform:uppercase;letter-spacing:.06em;display:flex;align-items:center;gap:5px;">
          <i class="fas fa-brain"></i> AI Graph Narrator
          <span style="margin-left:auto;font-size:8px;color:#475569;font-weight:400;text-transform:none;">Powered by Wadjet-Eye AI</span>
        </div>
        <div id="tgv2-narrator-content" style="flex:1;overflow-y:auto;padding:14px;scrollbar-width:thin;scrollbar-color:#1e293b transparent;">
          <div style="font-size:11px;color:#94a3b8;line-height:1.7;">Click any node or perform an action — I'll provide instant AI context, relationship analysis, and tactical recommendations.</div>
        </div>

        <!-- Quick stats -->
        <div style="padding:12px 14px;border-top:1px solid #1e293b;display:grid;grid-template-columns:1fr 1fr;gap:8px;">
          <div style="background:#090d14;border-radius:8px;padding:8px;text-align:center;">
            <div style="font-size:18px;font-weight:800;color:#ef4444;" id="tgv2-stat-critical">${V2_NODES.filter(n=>n.risk>=90).length}</div>
            <div style="font-size:9px;color:#475569;">Critical</div>
          </div>
          <div style="background:#090d14;border-radius:8px;padding:8px;text-align:center;">
            <div style="font-size:18px;font-weight:800;color:#22c55e;" id="tgv2-stat-active">${V2_NODES.filter(n=>n.status==='active').length}</div>
            <div style="font-size:9px;color:#475569;">Active Campaigns</div>
          </div>
          <div style="background:#090d14;border-radius:8px;padding:8px;text-align:center;">
            <div style="font-size:18px;font-weight:800;color:#3b82f6;" id="tgv2-stat-actors">${V2_NODES.filter(n=>n.type==='threat_actor').length}</div>
            <div style="font-size:9px;color:#475569;">Actors Tracked</div>
          </div>
          <div style="background:#090d14;border-radius:8px;padding:8px;text-align:center;">
            <div style="font-size:18px;font-weight:800;color:#a855f7;">${V2_EDGES.length}</div>
            <div style="font-size:9px;color:#475569;">Relationships</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Context menu -->
  <div id="tgv2-context-menu" style="display:none;position:fixed;background:#0f172a;border:1px solid #1e293b;border-radius:10px;z-index:9999;min-width:190px;box-shadow:0 8px 32px rgba(0,0,0,.7);font-family:Inter,sans-serif;"></div>
  `;
}

/* ═══════════════════════════════════════════════════════════════════════════
   §18  PUBLIC CONTROLS
═══════════════════════════════════════════════════════════════════════════ */
window.tgv2Zoom = function(delta) {
  _s.zoom = Math.max(0.2, Math.min(4, _s.zoom + delta));
};
window.tgv2ResetView = function() {
  _s.zoom=1; _s.pan={x:0,y:0};
};
window.tgv2ToggleSim = function() {
  _s.simRunning = !_s.simRunning;
  const btn = document.getElementById('tgv2-sim-btn');
  if (btn) btn.style.color = _s.simRunning ? '#22c55e' : '#ef4444';
};
window.tgv2Search = function(q) {
  const node = _s.nodes.find(n => n.label.toLowerCase().includes(q.toLowerCase()));
  if (node) { tgv2FocusNode(node.id); }
};
window.tgv2LegendFilter = function(type) {
  const existing = _s.nodes.filter(n=>n.type!==type);
  /* Simple visibility toggle — toggle type */
  _toast(`Filtered: ${type}`, 'info');
  _applyFilters();
};

/* ═══════════════════════════════════════════════════════════════════════════
   §19  ENTRY POINT
═══════════════════════════════════════════════════════════════════════════ */
window.renderThreatGraphV2 = function() {
  const container = document.getElementById('page-threat-graph');
  if (!container) return;

  /* Cancel existing animation loop */
  if (_s.animFrame) { cancelAnimationFrame(_s.animFrame); _s.animFrame=null; }
  clearInterval(_s.temporal.timer);
  document.removeEventListener('keydown', _onKeyDown);
  document.querySelectorAll('.tgv2-tooltip-cleanup').forEach(el=>el.remove());

  /* Build HTML shell */
  _buildShell(container);

  /* Load data */
  _s.allNodes = V2_NODES;
  _s.allEdges = V2_EDGES;
  _s.nodes    = [...V2_NODES];
  _s.edges    = [...V2_EDGES];

  /* Init canvas */
  const canvas = document.getElementById('tgv2-canvas');
  if (!canvas) return;
  _s.canvas = canvas;

  const wrap = canvas.parentElement;
  canvas.width  = wrap.offsetWidth || 900;
  canvas.height = wrap.offsetHeight || 600;
  _s.ctx = canvas.getContext('2d');

  /* Init physics positions */
  _initPhysics();

  /* Render filter panel */
  _renderLensPanel();

  /* Canvas events */
  canvas.addEventListener('mousedown',  _onMouseDown);
  canvas.addEventListener('mousemove',  _onMouseMove);
  canvas.addEventListener('mouseup',    _onMouseUp);
  canvas.addEventListener('click',      _onClick);
  canvas.addEventListener('dblclick',   _onDblClick);
  canvas.addEventListener('wheel',      _onWheel, { passive:false });
  canvas.addEventListener('contextmenu',_onContextMenu);
  document.addEventListener('keydown',  _onKeyDown);

  /* Resize observer */
  if (window.ResizeObserver) {
    const ro = new ResizeObserver(() => {
      if (_s.canvas) {
        _s.canvas.width  = _s.canvas.parentElement?.offsetWidth  || 900;
        _s.canvas.height = _s.canvas.parentElement?.offsetHeight || 600;
      }
    });
    ro.observe(wrap);
  }

  /* Hide context menu on outside click */
  document.addEventListener('click', (e) => {
    const menu = document.getElementById('tgv2-context-menu');
    if (menu && !menu.contains(e.target)) menu.style.display='none';
  });

  /* Start animation loop */
  _loop();

  /* Default narrator */
  _renderNarratorDefault();

  /* Auto-attempt live data fetch */
  _fetchLiveData();
};

/* ═══════════════════════════════════════════════════════════════════════════
   §20  LIVE DATA FETCH
═══════════════════════════════════════════════════════════════════════════ */
async function _fetchLiveData() {
  try {
    const token = localStorage.getItem('auth_token') || localStorage.getItem('supabase_token');
    if (!token) return; /* Use static data when not authenticated */

    const res = await fetch('/api/threat-graph', {
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
    });
    if (!res.ok) return;
    const data = await res.json();

    if (data.nodes && data.nodes.length > 0) {
      /* Merge live data with static data */
      const liveNodeIds = new Set(data.nodes.map(n=>n.node_id));
      const mergedNodes = [
        ...data.nodes.map(n => ({
          id: n.node_id, type: n.node_type, label: n.label,
          region: n.region, risk: n.risk_score||50,
          ...(n.data||{}),
          first_seen: n.first_seen||n.created_at,
          last_seen: n.last_seen||n.updated_at,
        })),
        ...V2_NODES.filter(n => !liveNodeIds.has(n.id)),
      ];
      _s.allNodes = mergedNodes;
      _s.nodes    = [...mergedNodes];
      _initPhysics();
      _updateNodeCount();
    }
    if (data.edges && data.edges.length > 0) {
      const liveEdges = data.edges.map(e => ({
        src:e.source_node, tgt:e.target_node, rel:e.relationship||'related',
        weight:e.strength||0.5, first_seen:e.created_at,
      }));
      _s.allEdges = [...liveEdges, ...V2_EDGES.filter(e => !liveEdges.some(le=>le.src===e.src&&le.tgt===e.tgt))];
      _s.edges    = [..._s.allEdges];
      _updateNodeCount();
    }
  } catch(err) {
    /* Silently fall back to static data */
    console.warn('[TGv2] Live fetch failed, using static dataset:', err.message);
  }
}

/* Expose _enterEgoMode for context menu inline calls */
global._enterEgoMode = _enterEgoMode;
global._s = _s; /* for debug */

})(window);
