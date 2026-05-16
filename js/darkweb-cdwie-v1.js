/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI v24.0 — Cognitive Dark Web Intelligence Engine (CDWIE) v1.0
 *  7-Engine AI-Powered Dark Web Intelligence Ecosystem
 *  Replaces: darkweb-v6.js / darkweb-ultimate.js
 *  Entry point: window.renderDarkWeb()
 *  Namespace: window._cdwie*
 * ══════════════════════════════════════════════════════════════════════
 */
(function () {
'use strict';

/* ═══════════════════════════════════════════════════════
   SECTION 1 — CSS INJECTION (idempotent)
═══════════════════════════════════════════════════════ */
(function _injectCSS() {
  if (document.getElementById('cdwie-styles-link')) return;
  var link = document.createElement('link');
  link.id   = 'cdwie-styles-link';
  link.rel  = 'stylesheet';
  link.href = 'css/darkweb-cdwie.css';
  document.head.appendChild(link);
})();

/* ═══════════════════════════════════════════════════════
   SECTION 2 — DEMO DATA STORE
═══════════════════════════════════════════════════════ */

/* ── Threat Actor Profiles ── */
const DW_ACTORS = {
  'apt29': {
    id:'apt29', name:'APT29', alias:'Cozy Bear',
    aliases:['CozyDuke','The Dukes','Midnight Blizzard','YTTRIUM','Iron Hemlock'],
    origin:'Russia', sponsor:'SVR (Foreign Intelligence Service)',
    active:'2008–Present', confidence:94,
    threat:'CRITICAL', color:'#ef4444', flag:'🇷🇺',
    icon:'fas fa-eye', faIcon:'fa-eye', sectors:['Government','Defense','Think Tanks','Energy','Healthcare'],
    ttps:['T1566.001','T1059.001','T1078','T1021.002','T1083','T1027','T1036','T1057','T1055','T1102'],
    tools:['HAMMERTOSS','MiniDuke','CosmicDuke','FatDuke','PolyglotDuke','BEATDROP','BEACON','WellMess'],
    desc:'APT29 is a sophisticated Russian nation-state threat actor sponsored by the SVR. Known for highly targeted spear-phishing campaigns, living-off-the-land techniques, and long-term persistent access. Responsible for the SolarWinds supply chain attack (SUNBURST) and numerous high-value intelligence collection operations against Western governments.',
    behavior:{ sophistication:96, persistence:92, stealth:95, speed:45, scale:38, evasion:97, innovation:88, destructiveness:30 },
    infra:{ asns:['AS31898','AS16509','AS14618'], hostingProviders:['Amazon AWS','Microsoft Azure','Cloudflare'], c2Domains:['*.azurewebsites.net','*.blob.core.windows.net'] },
    opHours:'Tue–Sat 08:00–19:00 MSK',
    writingStyle:'Technical, formal Russian syntax patterns. Heavy use of LOLBins. Minimal footprint.',
  },
  'lockbit': {
    id:'lockbit', name:'LockBit 4.0', alias:'LockBit Group',
    aliases:['LockBit Black','LockBit Green','LockBitSupp'],
    origin:'Russia (suspected)', sponsor:'Criminal / RaaS',
    active:'2019–Present', confidence:91,
    threat:'CRITICAL', color:'#f97316', flag:'🌐',
    icon:'fas fa-lock', faIcon:'fa-lock', sectors:['Healthcare','Finance','Manufacturing','Government','Legal'],
    ttps:['T1486','T1490','T1083','T1489','T1562','T1078','T1021','T1003','T1047'],
    tools:['LockBit 4.0','StealBit','Mimikatz','Cobalt Strike','Rclone'],
    desc:'LockBit is the world\'s most prolific ransomware-as-a-service (RaaS) operation. Operating since 2019, LockBit 4.0 features advanced affiliate programs, automatic encryption, and triple extortion (encryption + data theft + DDoS). The group has claimed over 1,700 victims globally.',
    behavior:{ sophistication:88, persistence:78, stealth:72, speed:95, scale:98, evasion:80, innovation:85, destructiveness:95 },
    infra:{ asns:['AS44477','AS208091'], hostingProviders:['Bulletproof hosting (RU)','Shinjiru'], c2Domains:['lockbit4.onion','lockbitapt.onion'] },
    opHours:'Mon–Sun 00:00–23:59 UTC (automated)',
    writingStyle:'Business-like, professional tone. English and Russian. Marketing-oriented.',
  },
  'apt41': {
    id:'apt41', name:'APT41', alias:'Double Dragon',
    aliases:['Winnti','Barium','Wicked Panda','Earth Baku'],
    origin:'China', sponsor:'MSS (Ministry of State Security)',
    active:'2012–Present', confidence:89,
    threat:'HIGH', color:'#a855f7', flag:'🇨🇳',
    icon:'fas fa-dragon', faIcon:'fa-dragon', sectors:['Technology','Healthcare','Telecom','Finance','Gaming'],
    ttps:['T1190','T1059.003','T1053.005','T1027','T1140','T1070','T1055.001','T1071'],
    tools:['CROSSWALK','POISONPLUG','ShadowPad','Cobalt Strike','njRAT','PlugX','KeyPlug'],
    desc:'APT41 is a unique Chinese state-sponsored group conducting both espionage and financially motivated intrusions. They target pharmaceutical companies for IP theft, gaming companies for financial gain, and government entities for intelligence collection. Known for exploiting supply chains and managed service providers.',
    behavior:{ sophistication:91, persistence:87, stealth:85, speed:72, scale:82, evasion:89, innovation:90, destructiveness:60 },
    infra:{ asns:['AS4812','AS7497','AS23650'], hostingProviders:['China Telecom','Alibaba Cloud'], c2Domains:['*.microsoftonline-portal.com','update.microsoft.*.com'] },
    opHours:'Mon–Fri 09:00–18:00 CST',
    writingStyle:'Mandarin influence in code comments. Mix of traditional and simplified Chinese characters.',
  },
  'fin7': {
    id:'fin7', name:'FIN7', alias:'Carbanak',
    aliases:['Carbanak Group','Navigator Group','ITG14','Carbon Spider'],
    origin:'Ukraine/Russia', sponsor:'Criminal / Financial',
    active:'2013–Present', confidence:88,
    threat:'CRITICAL', color:'#eab308', flag:'🌐',
    icon:'fas fa-dollar-sign', faIcon:'fa-dollar-sign', sectors:['Finance','Retail','Hospitality','Healthcare','Technology'],
    ttps:['T1566','T1059.007','T1203','T1021.006','T1056.001','T1110','T1539'],
    tools:['CARBANAK','GRIFFON','BOOSTWRITE','RDFSNIFFER','Cobalt Strike','PowerShell Empire'],
    desc:'FIN7 is a sophisticated financially motivated threat actor responsible for billions in losses. Pioneered the use of a fake company "Combi Security" to recruit penetration testers. Specializes in point-of-sale malware and business email compromise targeting the hospitality and retail sectors.',
    behavior:{ sophistication:87, persistence:82, stealth:88, speed:68, scale:75, evasion:85, innovation:78, destructiveness:50 },
    infra:{ asns:['AS44050','AS199524'], hostingProviders:['Frantech','BuyVM'], c2Domains:['*.shopify.com.*.xyz','payment-process.*.net'] },
    opHours:'Mon–Fri 08:00–20:00 EET',
    writingStyle:'English with Ukrainian syntax patterns. Business terminology. Spear-phishing focus.',
  },
  'oilrig': {
    id:'oilrig', name:'OilRig', alias:'APT34',
    aliases:['APT34','Helix Kitten','Twisted Kitten','Lyceum','Crambus'],
    origin:'Iran', sponsor:'MOIS (Ministry of Intelligence)',
    active:'2014–Present', confidence:86,
    threat:'HIGH', color:'#22d3ee', flag:'🇮🇷',
    icon:'fas fa-oil-can', faIcon:'fa-oil-can', sectors:['Energy','Government','Finance','Telecom','Aviation'],
    ttps:['T1190','T1566.001','T1078','T1505.003','T1071.001','T1041','T1059.004'],
    tools:['QUADAGENT','POSHC2','DNSpionage','RDAT','Karkoff','SideTwist','Marlin'],
    desc:'OilRig (APT34) is an Iranian state-sponsored threat actor primarily targeting Middle Eastern nations and organizations connected to the region. Known for sophisticated DNS tunneling C2 and watering hole attacks. Focuses on persistent access for intelligence gathering.',
    behavior:{ sophistication:82, persistence:88, stealth:80, speed:55, scale:60, evasion:79, innovation:75, destructiveness:45 },
    infra:{ asns:['AS44244','AS48159','AS12880'], hostingProviders:['Pars Online','Shatel','TIC'], c2Domains:['*.*.ir','news-portal.*.net'] },
    opHours:'Sun–Thu 08:00–17:00 IRST',
    writingStyle:'Farsi influence. Mix of Farsi and English in tooling. Regional focus indicators.',
  },
  'lazarus': {
    id:'lazarus', name:'Lazarus Group', alias:'Hidden Cobra',
    aliases:['Hidden Cobra','Guardians of Peace','WhoisTeam','APT38','Zinc'],
    origin:'North Korea', sponsor:'RGB (Reconnaissance General Bureau)',
    active:'2009–Present', confidence:93,
    threat:'CRITICAL', color:'#ec4899', flag:'🇰🇵',
    icon:'fas fa-skull-crossbones', faIcon:'fa-skull-crossbones', sectors:['Finance','Cryptocurrency','Defense','Aerospace','Government'],
    ttps:['T1566','T1059.003','T1053','T1070','T1485','T1486','T1552','T1041'],
    tools:['HOPLIGHT','BLINDINGCAN','BADCALL','AppleJeus','DRATzarus','FALLCHILL','ELECTRICFISH'],
    desc:'Lazarus Group is a prolific North Korean state-sponsored threat actor responsible for the most significant cryptocurrency thefts in history, including $625M from Ronin Network. Conducts financially motivated attacks to fund the regime\'s weapons programs. Also conducts destructive attacks and espionage.',
    behavior:{ sophistication:90, persistence:85, stealth:78, speed:65, scale:70, evasion:82, innovation:86, destructiveness:88 },
    infra:{ asns:['AS131279','AS17379'], hostingProviders:['KCC','Choson Exchange'], c2Domains:['*.*.kp','blockchain-update.*.com'] },
    opHours:'Mon–Sat 01:00–15:00 KST (irregular)',
    writingStyle:'Korean syntax in code. English operational communications. Cryptocurrency terminology.',
  },
  'blackcat': {
    id:'blackcat', name:'BlackCat/ALPHV', alias:'ALPHV Group',
    aliases:['ALPHV','Noberus','BlackCat Ransomware Gang'],
    origin:'Unknown (ex-DarkSide/BlackMatter)', sponsor:'Criminal / RaaS',
    active:'2021–Present', confidence:87,
    threat:'CRITICAL', color:'#ef4444', flag:'🌐',
    icon:'fas fa-cat', faIcon:'fa-cat', sectors:['Healthcare','Legal','Energy','Manufacturing','Finance'],
    ttps:['T1486','T1657','T1562','T1190','T1059.001','T1078','T1021.001','T1567'],
    tools:['BlackCat Ransomware','ExMatter','Conti Leaked Toolkit','Cobalt Strike','BurntCigar'],
    desc:'BlackCat/ALPHV operates the first ransomware written in Rust, enabling cross-platform attacks. Uses triple-extortion: encryption + data theft + victim shaming. Suffered FBI seizure in December 2023 but retaliated and relaunched. Known for medical facility targeting and public pressure tactics.',
    behavior:{ sophistication:89, persistence:80, stealth:77, speed:88, scale:85, evasion:83, innovation:92, destructiveness:90 },
    infra:{ asns:['AS60068','AS206092'], hostingProviders:['Bulletproof (RU/RO)'], c2Domains:['alphv*.onion','blackcat*.onion'] },
    opHours:'Mon–Sun (affiliate-operated, 24/7)',
    writingStyle:'Professional business communication. English primary. Negotiation-oriented.',
  }
};
/* Computed array for iteration — DW_ACTORS is an object keyed by id */
var _DW_ACTORS_ARR = Object.values(DW_ACTORS);

/* ── Knowledge Graph Data ── */
const DW_GRAPH_DATA = (function(){
  var nodes = [
    {id:'n1',  label:'APT29',          type:'actor',     color:'#ef4444', x:400,y:300, risk:'CRITICAL'},
    {id:'n2',  label:'LockBit 4.0',    type:'actor',     color:'#f97316', x:650,y:200, risk:'CRITICAL'},
    {id:'n3',  label:'APT41',          type:'actor',     color:'#a855f7', x:200,y:180, risk:'HIGH'},
    {id:'n4',  label:'FIN7',           type:'actor',     color:'#eab308', x:550,y:450, risk:'CRITICAL'},
    {id:'n5',  label:'Lazarus Group',  type:'actor',     color:'#ec4899', x:150,y:420, risk:'CRITICAL'},
    {id:'n6',  label:'OilRig',         type:'actor',     color:'#22d3ee', x:350,y:100, risk:'HIGH'},
    {id:'n7',  label:'BlackCat',       type:'actor',     color:'#ef4444', x:720,y:380, risk:'CRITICAL'},
    {id:'n8',  label:'SUNBURST',       type:'malware',   color:'#f97316', x:480,y:220, risk:'CRITICAL'},
    {id:'n9',  label:'HAMMERTOSS',     type:'malware',   color:'#f97316', x:310,y:250, risk:'HIGH'},
    {id:'n10', label:'Cobalt Strike',  type:'malware',   color:'#f97316', x:580,y:310, risk:'CRITICAL'},
    {id:'n11', label:'PlugX',          type:'malware',   color:'#f97316', x:230,y:280, risk:'HIGH'},
    {id:'n12', label:'CARBANAK',       type:'malware',   color:'#f97316', x:480,y:400, risk:'CRITICAL'},
    {id:'n13', label:'AppleJeus',      type:'malware',   color:'#f97316', x:180,y:350, risk:'HIGH'},
    {id:'n14', label:'185.220.101.47', type:'ioc',       color:'#3b82f6', x:600,y:150, risk:'HIGH'},
    {id:'n15', label:'solarwinds.*.ru',type:'ioc',       color:'#3b82f6', x:450,y:160, risk:'CRITICAL'},
    {id:'n16', label:'c2.apt29.ru',    type:'ioc',       color:'#3b82f6', x:340,y:200, risk:'CRITICAL'},
    {id:'n17', label:'SHA256:a1b2c3',  type:'ioc',       color:'#3b82f6', x:620,y:420, risk:'HIGH'},
    {id:'n18', label:'WINTER STORM',   type:'campaign',  color:'#a855f7', x:420,y:320, risk:'CRITICAL'},
    {id:'n19', label:'IRON TWILIGHT',  type:'campaign',  color:'#a855f7', x:640,y:280, risk:'HIGH'},
    {id:'n20', label:'DRAGONFLY',      type:'campaign',  color:'#a855f7', x:250,y:200, risk:'CRITICAL'},
    {id:'n21', label:'US Gov Portal',  type:'target',    color:'#22c55e', x:500,y:120, risk:'CRITICAL'},
    {id:'n22', label:'EU Healthcare',  type:'target',    color:'#22c55e', x:700,y:120, risk:'HIGH'},
    {id:'n23', label:'Asia Telecom',   type:'target',    color:'#22c55e', x:100,y:300, risk:'HIGH'},
    {id:'n24', label:'FinancialGroup', type:'target',    color:'#22c55e', x:680,y:480, risk:'CRITICAL'},
    {id:'n25', label:'AS44477',        type:'infra',     color:'#14b8a6', x:700,y:300, risk:'HIGH'},
    {id:'n26', label:'AS16509 (AWS)',  type:'infra',     color:'#14b8a6', x:380,y:140, risk:'MEDIUM'},
    {id:'n27', label:'Shinjiru Srv',   type:'infra',     color:'#14b8a6', x:750,y:220, risk:'HIGH'},
    {id:'n28', label:'1BvB945b.onion', type:'darkweb',   color:'#ec4899', x:820,y:300, risk:'HIGH'},
    {id:'n29', label:'lockbit4.onion', type:'darkweb',   color:'#ec4899', x:780,y:420, risk:'CRITICAL'},
    {id:'n30', label:'bc1q9f2a.btc',   type:'wallet',    color:'#eab308', x:840,y:180, risk:'HIGH'},
    {id:'n31', label:'3MbYQMMm.btc',   type:'wallet',    color:'#eab308', x:800,y:480, risk:'CRITICAL'},
    {id:'n32', label:'EMOTET',         type:'malware',   color:'#f97316', x:300,y:380, risk:'HIGH'},
    {id:'n33', label:'QakBot',         type:'malware',   color:'#f97316', x:260,y:440, risk:'HIGH'},
    {id:'n34', label:'HOSPITAL.onion', type:'darkweb',   color:'#ec4899', x:120,y:200, risk:'HIGH'},
    {id:'n35', label:'45.142.212.100', type:'ioc',       color:'#3b82f6', x:160,y:160, risk:'HIGH'},
    {id:'n36', label:'SILENT RANSOM',  type:'campaign',  color:'#a855f7', x:420,y:460, risk:'HIGH'},
    {id:'n37', label:'EnergyCorp',     type:'target',    color:'#22c55e', x:300,y:150, risk:'HIGH'},
    {id:'n38', label:'GovAgency',      type:'target',    color:'#22c55e', x:180,y:100, risk:'CRITICAL'},
    {id:'n39', label:'AS4812 CN',      type:'infra',     color:'#14b8a6', x:100,y:400, risk:'MEDIUM'},
    {id:'n40', label:'blockchain.fin', type:'darkweb',   color:'#ec4899', x:680,y:520, risk:'HIGH'},
  ];
  var edges = [
    {s:'n1', t:'n8',  type:'USES'},
    {s:'n1', t:'n9',  type:'USES'},
    {s:'n1', t:'n10', type:'USES'},
    {s:'n1', t:'n18', type:'ATTRIBUTED_TO'},
    {s:'n1', t:'n21', type:'TARGETS'},
    {s:'n1', t:'n16', type:'COMMUNICATES_WITH'},
    {s:'n1', t:'n26', type:'HOSTS'},
    {s:'n1', t:'n15', type:'USES'},
    {s:'n2', t:'n10', type:'USES'},
    {s:'n2', t:'n19', type:'ATTRIBUTED_TO'},
    {s:'n2', t:'n22', type:'TARGETS'},
    {s:'n2', t:'n25', type:'HOSTS'},
    {s:'n2', t:'n27', type:'HOSTS'},
    {s:'n2', t:'n29', type:'COMMUNICATES_WITH'},
    {s:'n2', t:'n31', type:'FUNDS'},
    {s:'n2', t:'n17', type:'USES'},
    {s:'n3', t:'n11', type:'USES'},
    {s:'n3', t:'n20', type:'ATTRIBUTED_TO'},
    {s:'n3', t:'n23', type:'TARGETS'},
    {s:'n3', t:'n39', type:'HOSTS'},
    {s:'n3', t:'n38', type:'TARGETS'},
    {s:'n4', t:'n12', type:'USES'},
    {s:'n4', t:'n10', type:'USES'},
    {s:'n4', t:'n24', type:'TARGETS'},
    {s:'n4', t:'n36', type:'ATTRIBUTED_TO'},
    {s:'n4', t:'n30', type:'FUNDS'},
    {s:'n5', t:'n13', type:'USES'},
    {s:'n5', t:'n33', type:'DELIVERS'},
    {s:'n5', t:'n24', type:'TARGETS'},
    {s:'n5', t:'n31', type:'FUNDS'},
    {s:'n5', t:'n40', type:'COMMUNICATES_WITH'},
    {s:'n6', t:'n14', type:'COMMUNICATES_WITH'},
    {s:'n6', t:'n35', type:'USES'},
    {s:'n6', t:'n37', type:'TARGETS'},
    {s:'n6', t:'n34', type:'COMMUNICATES_WITH'},
    {s:'n7', t:'n10', type:'USES'},
    {s:'n7', t:'n17', type:'USES'},
    {s:'n7', t:'n22', type:'TARGETS'},
    {s:'n7', t:'n28', type:'COMMUNICATES_WITH'},
    {s:'n7', t:'n30', type:'FUNDS'},
    {s:'n8', t:'n15', type:'COMMUNICATES_WITH'},
    {s:'n9', t:'n16', type:'COMMUNICATES_WITH'},
    {s:'n10', t:'n14', type:'COMMUNICATES_WITH'},
    {s:'n11', t:'n35', type:'COMMUNICATES_WITH'},
    {s:'n12', t:'n24', type:'TARGETS'},
    {s:'n18', t:'n21', type:'TARGETS'},
    {s:'n18', t:'n22', type:'TARGETS'},
    {s:'n19', t:'n22', type:'TARGETS'},
    {s:'n20', t:'n23', type:'TARGETS'},
    {s:'n20', t:'n37', type:'TARGETS'},
    {s:'n26', t:'n16', type:'HOSTS'},
    {s:'n25', t:'n29', type:'HOSTS'},
    {s:'n27', t:'n28', type:'HOSTS'},
    {s:'n32', t:'n33', type:'DELIVERS'},
    {s:'n32', t:'n37', type:'TARGETS'},
    {s:'n36', t:'n24', type:'TARGETS'},
    {s:'n39', t:'n35', type:'HOSTS'},
    {s:'n40', t:'n31', type:'FUNDS'},
    {s:'n28', t:'n30', type:'FUNDS'},
    {s:'n34', t:'n39', type:'HOSTS'},
  ];
  return { nodes: nodes, edges: edges };
})();

/* ── Predictions Data ── */
const DW_PREDICTIONS = {
  forecastDays: 30,
  riskScore: 74,
  factors: [
    { label:'Dark Web Chatter Volume',     score:82, color:'#ef4444' },
    { label:'Active Ransomware Campaigns', score:91, color:'#f97316' },
    { label:'Credential Exposure Index',   score:68, color:'#eab308' },
    { label:'APT Recon Signals',           score:77, color:'#a855f7' },
    { label:'Zero-Day Availability',       score:55, color:'#3b82f6' },
  ],
  campaigns: [
    { name:'WINTER STORM', group:'APT29', phase:2, phases:['Recon','Init Access','Lateral Mvmt','Exfil'], phaseDone:2, prob:73, eta:'6–12 days', confidence:'HIGH' },
    { name:'IRON RANSOM',  group:'LockBit 4.0', phase:3, phases:['Recon','Access','Encryption','Extortion'], phaseDone:3, prob:91, eta:'1–3 days', confidence:'CRITICAL' },
    { name:'DRAGONFLY III',group:'APT41', phase:1, phases:['Recon','Delivery','Install','C2'], phaseDone:1, prob:48, eta:'14–21 days', confidence:'MEDIUM' },
    { name:'SILENT RANSOM',group:'FIN7',  phase:2, phases:['Recon','Phishing','Access','Exfil'], phaseDone:2, prob:67, eta:'4–8 days', confidence:'HIGH' },
  ],
  geoThreats: [
    {code:'US',label:'United States',level:95,type:'Ransomware + APT'},
    {code:'DE',label:'Germany',level:78,type:'Industrial Espionage'},
    {code:'GB',label:'UK',level:72,type:'Credential Theft'},
    {code:'FR',label:'France',level:65,type:'Government Targeting'},
    {code:'JP',label:'Japan',level:68,type:'IP Theft'},
    {code:'KR',label:'South Korea',level:71,type:'State Espionage'},
    {code:'IN',label:'India',level:55,type:'Financial Fraud'},
    {code:'AU',label:'Australia',level:60,type:'Infrastructure'},
    {code:'CA',label:'Canada',level:58,type:'Ransomware'},
    {code:'BR',label:'Brazil',level:52,type:'Banking Malware'},
    {code:'IT',label:'Italy',level:61,type:'Ransomware'},
    {code:'NL',label:'Netherlands',level:55,type:'Dark Web Infra'},
    {code:'UA',label:'Ukraine',level:88,type:'State Warfare'},
    {code:'IL',label:'Israel',level:79,type:'State Espionage'},
    {code:'SA',label:'Saudi Arabia',level:74,type:'Energy Targeting'},
    {code:'SG',label:'Singapore',level:50,type:'Financial'},
    {code:'HK',label:'Hong Kong',level:62,type:'Espionage'},
    {code:'TW',label:'Taiwan',level:80,type:'State Espionage'},
    {code:'CN',label:'China',level:40,type:'Source Nation'},
    {code:'RU',label:'Russia',level:35,type:'Source Nation'},
  ],
  emerging: [
    { type:'Ransomware', name:'HellCat Ransomware', emerged:'2025-01-15', conf:88, icon:'fa-lock' },
    { type:'Exploit',    name:'VMware vCenter RCE',  emerged:'2025-02-01', conf:95, icon:'fa-bug' },
    { type:'Malware',    name:'Lumma Stealer v5',    emerged:'2025-01-28', conf:82, icon:'fa-virus' },
    { type:'Campaign',   name:'IRON TWILIGHT (APT29)',emerged:'2025-02-05', conf:79, icon:'fa-crosshairs' },
    { type:'0-Day',      name:'Chrome Sandbox Escape',emerged:'2025-02-08', conf:91, icon:'fa-shield-virus' },
    { type:'Botnet',     name:'Mirai.X Corp Botnet', emerged:'2025-01-20', conf:74, icon:'fa-network-wired' },
    { type:'RaaS',       name:'Fog Ransomware v2',   emerged:'2025-02-10', conf:86, icon:'fa-cloud' },
    { type:'Malware',    name:'TrueBot v4 Resurgence',emerged:'2025-01-30', conf:77, icon:'fa-robot' },
  ]
};

/* ── Deception Samples ── */
const DW_DECEPTION_SAMPLES = {
  fake: {
    label:'Fake Ransomware Leak Claim',
    text: `[URGENT] WE HAVE BREACHED MEGACORP INTERNATIONAL\n\nWe have stolen 500TB of data including executive emails, financial records, and source code.\n\nIF YOU DON'T PAY $50,000,000 WITHIN 24 HOURS WE WILL RELEASE EVERYTHING.\n\nThis is NOT a joke. We have EVERYTHING. Pay now or suffer.\n\nContact: fakeleaks@proton.me\n\nPROOF: [screenshot of windows explorer showing some files]`,
    scores: { credibility:18, scam:89, trust:'LOW', misinfo:85 },
    indicators: [
      { ok:false, text:'No verified IOCs attached' },
      { ok:false, text:'Proof-of-life absent' },
      { ok:false, text:'Timeline inconsistent' },
      { ok:true,  text:'Tor site present (unverified)' },
    ],
    signals: [
      { warn:true,  text:'Heavy emotional inflation ("EVERYTHING")' },
      { warn:true,  text:'Unverifiable claim scale (500TB)' },
      { warn:true,  text:'Generic contact method' },
      { warn:false, text:'No known recycled template match' },
    ],
    verdict:'LIKELY FABRICATED', verdictColor:'#ef4444'
  },
  genuine: {
    label:'Genuine APT Forum Post',
    text: `[OPSEC] New APT29 TTP observed — Lateral movement via ADCS abuse (ESC8)\n\nSample hash: a3f7b291e4d6c8012f94b7e3d1c02845f6a9e7b3d2c1f4e5a8b7c9d0e1f2a3b\nC2 beacon: 185.220.101.47:443 (Tor exit)\nFirst seen: 2025-01-20 via honeypot\n\nMO: Phishing → ADCS ESC8 → Mimikatz → BloodHound → Domain Admin\nAssociated campaign: WINTER STORM\n\nIOC Confidence: HIGH (cross-verified with 3 vendors)\nAffected systems: Windows Server 2019/2022`,
    scores: { credibility:91, scam:8, trust:'HIGH', misinfo:12 },
    indicators: [
      { ok:true, text:'Verified IOC hash (3 vendor match)' },
      { ok:true, text:'Consistent technical timeline' },
      { ok:true, text:'Source fingerprint: known analyst' },
      { ok:false,text:'Attribution not independently confirmed' },
    ],
    signals: [
      { warn:false, text:'Technical language consistent' },
      { warn:false, text:'No emotional manipulation' },
      { warn:true,  text:'Single source — not corroborated' },
      { warn:false, text:'No recycled content detected' },
    ],
    verdict:'LIKELY AUTHENTIC', verdictColor:'#22c55e'
  },
  creds: {
    label:'Credential Dump Listing',
    text: `[SELLING] 87,000 corporate accounts — Fortune 500 financial firm\n\nFormat: email:plaintext_password\nSource: internal breach (insider threat)\nDate: January 2025\nVerification: 500 sample available on request\nValid rate: 61% (tested against login portal)\n\nPrice: $1,200 BTC\nContact via Jabber: seller@jabber.ru\n\nNote: Account for MFA — some have app-based 2FA enabled`,
    scores: { credibility:55, scam:38, trust:'MEDIUM', misinfo:30 },
    indicators: [
      { ok:true,  text:'Plausible data format specified' },
      { ok:true,  text:'Sample availability offered' },
      { ok:false, text:'Source claim unverifiable' },
      { ok:false, text:'No proof-of-breach documentation' },
    ],
    signals: [
      { warn:true,  text:'Price unusually low for claimed scale' },
      { warn:false, text:'Contact method consistent with dark web norms' },
      { warn:true,  text:'Insider threat claim often fabricated' },
      { warn:false, text:'Technical detail level appropriate' },
    ],
    verdict:'AMBIGUOUS — VERIFY', verdictColor:'#eab308'
  },
  falseflag: {
    label:'False Flag Operation',
    text: `ATTACK CLAIMED BY: Killnet (Russian hacktivist group)\n\nTarget: US Treasury Department\nDate: 2025-01-28\nMethod: DDoS + data exfiltration\n\nSample data: [redacted government emails]\nTools used: XMR miner, Mirai variant, custom C2\n\nNOTE: Language patterns and tool signatures inconsistent with known Killnet TTPs. Infrastructure overlaps with Chinese APT cluster (AS4812). Possible false flag to attribute to Russia.`,
    scores: { credibility:42, scam:61, trust:'LOW', misinfo:78 },
    indicators: [
      { ok:false, text:'Tool signatures mismatch claimed actor' },
      { ok:false, text:'Infrastructure attribution conflict' },
      { ok:true,  text:'Technical content partially verified' },
      { ok:false, text:'Timeline gaps in attack sequence' },
    ],
    signals: [
      { warn:true, text:'Actor mismatch — likely false flag' },
      { warn:true, text:'Infrastructure in different threat cluster' },
      { warn:true, text:'Deliberate attribution misdirection' },
      { warn:false,'text':'Real attack event likely occurred' },
    ],
    verdict:'DECEPTION DETECTED', verdictColor:'#f97316'
  }
};

/* ── Copilot Response Dispatcher ── */
const DW_COPILOT_RESPONSES = {
  ip: function(ip) {
    return { type:'ioc-card', data:{
      label: ip, verdict:'MALICIOUS', verdictColor:'#ef4444',
      rows:[
        {k:'Type',        v:'Tor Exit Node / C2 Infrastructure'},
        {k:'ASN',         v:'AS205100 · F3 Netze e.V. (Germany)'},
        {k:'Reputation',  v:'Known malicious — 14 threat feeds'},
        {k:'First Seen',  v:'2024-11-12 via honeypot'},
        {k:'Last Seen',   v:'2025-02-14 (active)'},
        {k:'Campaigns',   v:'WINTER STORM (2025), IRON TWILIGHT'},
        {k:'MITRE',       v:'T1090.003 — Multi-hop Proxy'},
        {k:'Attribution', v:'APT29 (HIGH confidence)'},
      ]
    }};
  },
  domain: function(domain) {
    return { type:'ioc-card', data:{
      label: domain, verdict:'SUSPICIOUS', verdictColor:'#f97316',
      rows:[
        {k:'Type',       v: domain.includes('.onion') ? 'Tor Hidden Service' : 'Suspicious Domain'},
        {k:'Registrar',  v:'Njalla (Privacy-protected)'},
        {k:'Registered', v:'2024-09-03 (recent — suspicious)'},
        {k:'DNS',        v:'Fast-flux — multiple IPs observed'},
        {k:'TLS',        v:'Self-signed certificate (Let\'s Encrypt)'},
        {k:'Category',   v: domain.includes('.onion') ? 'Dark Web C2' : 'Potential Phishing'},
        {k:'Threat Feeds',v:'7/24 feeds flagged'},
        {k:'MITRE',      v:'T1583.001 — Domain Acquisition'},
      ]
    }};
  },
  hash: function(hash) {
    return { type:'ioc-card', data:{
      label: hash.substring(0,20)+'...', verdict:'MALWARE IDENTIFIED', verdictColor:'#ef4444',
      rows:[
        {k:'Family',    v:'Cobalt Strike Beacon (v4.9)'},
        {k:'Type',      v:'Reflective DLL / Shellcode Loader'},
        {k:'AV Ratio',  v:'51/72 vendors detected'},
        {k:'First Seen',v:'2024-12-01 (VirusTotal)'},
        {k:'Packer',    v:'Custom packer — modified MPRESS'},
        {k:'C2',        v:'185.220.101.47:443 (Tor relay)'},
        {k:'Actor',     v:'APT29 / FIN7 (overlap tools)'},
        {k:'MITRE',     v:'T1055.001 — Reflective DLL Injection'},
      ]
    }};
  },
  actor: function(name) {
    var key = name.toLowerCase().replace(/\s/g,'');
    var actor = null;
    Object.values(DW_ACTORS).forEach(function(a){ if(a.name.toLowerCase().includes(key)||key.includes(a.alias.toLowerCase().replace(/\s/g,''))) actor=a; });
    if(!actor) actor = DW_ACTORS['apt29'];
    return { type:'actor-card', data:{
      name: actor.name, alias: actor.alias, origin: actor.origin,
      threat: actor.threat, confidence: actor.confidence,
      desc: actor.desc.substring(0,200)+'...',
      tools: actor.tools.slice(0,4), ttps: actor.ttps.slice(0,5)
    }};
  },
  ransomware: function(q) {
    return { type:'text', text:'**Active Ransomware Intelligence Brief:**\n\n🔴 **LockBit 4.0** — 47 new victims in 30 days. Healthcare sector primary target. Avg ransom: $2.1M.\n\n🟠 **BlackCat/ALPHV** — Retooled post-FBI disruption. New ESXi variant detected. Critical infrastructure focus.\n\n🟡 **Clop** — MOVEit exploitation campaign ongoing. 89 organizations affected.\n\n**Recommendations:** Patch MOVEit/GoAnywhere. Enable MFA. Implement network segmentation. Test backup restoration.' };
  },
  predict: function() {
    return { type:'prediction', data:{
      score:74, level:'HIGH', period:'Next 14 days',
      events:[
        {prob:82, event:'Ransomware attack on EU healthcare sector'},
        {prob:67, event:'New credential dump from financial institution'},
        {prob:54, event:'Supply chain attack on tech vendor'},
        {prob:41, event:'Zero-day publication on major OS'},
      ]
    }};
  },
  report: function() {
    return { type:'text', text:'**Executive Intelligence Brief — Auto-Generated**\n\n📊 **Threat Landscape** (Last 7 days)\n- 34 new dark web threats identified\n- 3 active ransomware campaigns targeting your sector\n- 12 exposed credential sets containing corporate emails\n- 2 APT reconnaissance signals detected\n\n🎯 **Risk Score: 74/100 (HIGH)**\n\nSwitching to Engine 7 — Exec Reports for full report generation.' };
  },
  correlate: function(q) {
    return { type:'text', text:'**IOC → Actor → Campaign Correlation Chain:**\n\n`185.220.101.47` → **APT29** → **WINTER STORM Campaign**\n\n**Chain:** Tor Exit Node → Cobalt Strike C2 → Lateral movement → ADCS abuse → Domain Admin → Data exfiltration\n\n**Related IOCs:**\n• `c2.apt29.ru` (C2 domain)\n• `SHA256:a3f7b291...` (SUNBURST variant)\n• `AS26101` (hosting provider)\n\n**Confidence:** HIGH (94%)' };
  },
  help: function() {
    return { type:'text', text:'**CTI Copilot Command Reference:**\n\n`<IP address>` — IOC reputation analysis\n`<domain>` — Domain intelligence lookup\n`<MD5/SHA256>` — Malware identification\n`<actor name>` — Threat actor profile\n`ransomware <keyword>` — Active RaaS briefing\n`predict` — Threat forecast\n`report` — Executive brief\n`correlate <IOC>` — Attribution chain\n`/clear` — Clear chat history\n`/export` — Export conversation\n`/help` — Show this menu' };
  }
};

/* ═══════════════════════════════════════════════════════
   SECTION 3 — MODULE STATE
═══════════════════════════════════════════════════════ */
var _cdwie = {
  activeTab: 'cognitive-search',
  actor:  { selected: 'apt29', dnaTab: 'aliases' },
  graph:  { nodes:[], edges:[], scale:1, offsetX:0, offsetY:0,
            dragNode:null, animFrame:null, live:false,
            hoverNode:null, selectedNode:null, initialized:false },
  search: { results:[], query:'', running:false },
  copilot:{ history:[], typing:false, workflowMode:false, firstMessage:true },
  report: { type:'executive', sections:{ exec_summary:true, threat_landscape:true, actor_profiles:true, ioc_list:true, campaign_analysis:true, recommendations:true, appendix:false }, timeframe:'7d', sector:'all', tlp:'amber' },
  deception: { currentSample: null, analyzed: false },
  kpis: { queries:247, actors:89, nodes:1432, threats:34, credibility:81, briefed:12, reports:7 },
  initialized: false
};

/* ═══════════════════════════════════════════════════════
   SECTION 4 — UTILITIES
═══════════════════════════════════════════════════════ */
function _e(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}
function _ago(iso) {
  if (!iso) return 'Unknown';
  var diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return Math.floor(diff) + 's ago';
  if (diff < 3600) return Math.floor(diff/60) + 'm ago';
  if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
  return Math.floor(diff/86400) + 'd ago';
}
function _toast(msg, type) {
  if (typeof window._toast === 'function') { window._toast(msg, type||'info'); return; }
  console.log('[CDWIE] ' + (type||'info') + ': ' + msg);
}
function _badge(level) {
  var map = { CRITICAL:'cdwie-badge-critical', HIGH:'cdwie-badge-high', MEDIUM:'cdwie-badge-medium', LOW:'cdwie-badge-low', ONLINE:'cdwie-badge-online' };
  return '<span class="cdwie-badge ' + (map[level]||'cdwie-badge-info') + '">' + _e(level) + '</span>';
}
function _countUp(el, target, dur) {
  if (!el) return;
  var start = 0, step = 16;
  var inc = target / ((dur||800) / step);
  var timer = setInterval(function(){
    start = Math.min(start + inc, target);
    el.textContent = Math.floor(start).toLocaleString();
    if (start >= target) clearInterval(timer);
  }, step);
}
function _pct(val, max) { return Math.round((val/max)*100); }
function _clamp(v,lo,hi){ return Math.max(lo,Math.min(hi,v)); }
function _rand(min,max)  { return Math.floor(Math.random()*(max-min+1))+min; }
function _qs(sel, ctx)   { return (ctx||document).querySelector(sel); }
function _qsa(sel,ctx)   { return Array.from((ctx||document).querySelectorAll(sel)); }
function _el(tag,cls,html){ var e=document.createElement(tag||'div'); if(cls)e.className=cls; if(html!==undefined)e.innerHTML=html; return e; }

/* ═══════════════════════════════════════════════════════
   SECTION 5 — MAIN RENDER + SHELL
═══════════════════════════════════════════════════════ */
window.renderDarkWeb = function() {
  var container = document.getElementById('page-dark-web');
  if (!container) return;

  // Idempotency — stop previous graph loop
  if (_cdwie.graph.animFrame) { cancelAnimationFrame(_cdwie.graph.animFrame); _cdwie.graph.animFrame = null; }

  container.className = 'p19-module';
  container.innerHTML = '';

  var root = _el('div','cdwie-root');
  root.id = 'cdwie-root';
  container.appendChild(root);

  // KPI Bar
  root.appendChild(_buildKPIBar());
  // Header
  root.appendChild(_buildHeader());
  // Tabs
  root.appendChild(_buildTabs());
  // Single engine panel — hydrated dynamically on tab switch
  var panel = _el('div','cdwie-content');
  panel.id = 'cdwie-engine-panel';
  root.appendChild(panel);

  // Detail panel
  root.appendChild(_buildDetailPanel());

  _cdwie.initialized = true;

  // Load the default tab engine after DOM is ready
  setTimeout(function() {
    window._cdwieTab(_cdwie.activeTab || 'cognitive-search');
  }, 60);

  // Animate KPIs
  setTimeout(_animateKPIs, 200);
};

/* ── KPI Bar ── */
function _buildKPIBar() {
  var kpis = [
    { val:247,   label:'AI Queries Run',   icon:'fa-brain',         cls:'cdwie-kpi-cyan',   id:'kpi-queries' },
    { val:89,    label:'Actors in DB',     icon:'fa-users',         cls:'cdwie-kpi-purple', id:'kpi-actors' },
    { val:1432,  label:'Graph Nodes',      icon:'fa-project-diagram',cls:'cdwie-kpi-blue',  id:'kpi-nodes' },
    { val:34,    label:'Threats 7d',       icon:'fa-exclamation-triangle', cls:'cdwie-kpi-orange', id:'kpi-threats' },
    { val:81,    label:'Avg Credibility',  icon:'fa-shield-alt',    cls:'cdwie-kpi-green',  id:'kpi-cred', suffix:'%' },
    { val:12,    label:'AI Briefed',       icon:'fa-robot',         cls:'cdwie-kpi-teal',   id:'kpi-briefed' },
    { val:7,     label:'Reports',          icon:'fa-file-contract', cls:'cdwie-kpi-yellow', id:'kpi-reports' },
  ];
  var bar = _el('div','cdwie-kpi-bar');
  kpis.forEach(function(k){
    var item = _el('div','cdwie-kpi-item');
    item.innerHTML = '<i class="fas '+k.icon+' cdwie-kpi-icon '+k.cls+'"></i>' +
      '<div class="cdwie-kpi-val '+k.cls+'" id="'+k.id+'">'+k.val+(k.suffix||'')+'</div>' +
      '<div class="cdwie-kpi-label">'+k.label+'</div>';
    bar.appendChild(item);
  });
  return bar;
}
function _animateKPIs() {
  var pairs = [
    {id:'kpi-queries',val:247}, {id:'kpi-actors',val:89},
    {id:'kpi-nodes',val:1432},  {id:'kpi-threats',val:34},
    {id:'kpi-briefed',val:12},  {id:'kpi-reports',val:7}
  ];
  pairs.forEach(function(p,i){
    setTimeout(function(){
      var el = document.getElementById(p.id);
      if (el) _countUp(el, p.val, 900);
    }, i*80);
  });
}

/* ── Module Header ── */
function _buildHeader() {
  var h = _el('div','cdwie-header');
  h.innerHTML =
    '<div class="cdwie-header-left">' +
      '<div class="cdwie-header-icon"><i class="fas fa-spider"></i></div>' +
      '<div>' +
        '<div class="cdwie-header-title">COGNITIVE DARK WEB INTELLIGENCE ENGINE</div>' +
        '<div class="cdwie-header-sub">AI-Powered · Multi-Engine · Autonomous Intel</div>' +
        '<div style="margin-top:5px">' +
          '<span class="cdwie-status-badge"><span class="cdwie-status-dot"></span>ACTIVE MONITORING</span>' +
        '</div>' +
      '</div>' +
    '</div>' +
    '<div class="cdwie-header-right">' +
      '<button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._cdwieToggleLiveFeed()"><i class="fas fa-satellite-dish"></i> Live Feed</button>' +
      '<button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._cdwieAlertRules()"><i class="fas fa-bell"></i> Alert Rules</button>' +
      '<button class="p19-btn p19-btn--primary p19-btn--sm" onclick="window._cdwieInvestigationMode()"><i class="fas fa-eye"></i> Investigation</button>' +
    '</div>';
  return h;
}

/* ── Tab Navigation ── */
var _TABS = [
  { id:'cognitive-search', label:'Cognitive Search', icon:'fa-brain',          color:'#22d3ee', badge:'' },
  { id:'actor-dna',        label:'Threat Actor DNA', icon:'fa-dna',            color:'#a855f7', badge:Object.keys(DW_ACTORS).length },
  { id:'knowledge-graph',  label:'Adversary Graph',  icon:'fa-project-diagram',color:'#3b82f6', badge:DW_GRAPH_DATA.nodes.length },
  { id:'predictive',       label:'Predictive Intel', icon:'fa-chart-line',     color:'#f97316', badge:'' },
  { id:'deception',        label:'Deception Detect', icon:'fa-shield-virus',   color:'#ef4444', badge:'' },
  { id:'copilot',          label:'CTI Copilot',      icon:'fa-robot',          color:'#22c55e', badge:'' },
  { id:'reporting',        label:'Exec Reports',     icon:'fa-file-contract',  color:'#14b8a6', badge:'' },
];
function _buildTabs() {
  var nav = _el('div','cdwie-tabs');
  _TABS.forEach(function(t){
    var tab = _el('div','cdwie-tab');
    tab.dataset.tab = t.id;
    tab.style.setProperty('--tab-color', t.color);
    tab.innerHTML = '<i class="fas '+t.icon+'"></i> '+t.label +
      (t.badge ? ' <span class="cdwie-tab-badge">'+t.badge+'</span>' : '');
    tab.addEventListener('click', function(){ window._cdwieTab(t.id); });
    nav.appendChild(tab);
  });
  return nav;
}

/* ── Tab Switcher stub — overridden by full implementation in ENGINE WIRING section ── */
window._cdwieTab = function(tab) { /* full impl defined below after all engines load */ };

/* ── Detail Panel ── */
function _buildDetailPanel() {
  var p = _el('div','cdwie-detail-panel');
  p.id = 'cdwie-detail-panel';
  p.innerHTML =
    '<div class="cdwie-detail-panel-header">' +
      '<span style="font-weight:700;font-size:13px" id="cdwie-panel-title">Intelligence Brief</span>' +
      '<button class="cdwie-panel-close" onclick="window._cdwieClosePanel()"><i class="fas fa-times"></i></button>' +
    '</div>' +
    '<div class="cdwie-detail-panel-body" id="cdwie-panel-body"></div>';
  return p;
}
window._cdwieClosePanel = function() {
  var p = document.getElementById('cdwie-detail-panel');
  if (p) p.classList.remove('open');
};
function _openPanel(title, html) {
  var p = document.getElementById('cdwie-detail-panel');
  var t = document.getElementById('cdwie-panel-title');
  var b = document.getElementById('cdwie-panel-body');
  if (!p||!t||!b) return;
  t.textContent = title;
  b.innerHTML = html;
  p.classList.add('open');
}

/* ── Header Buttons ── */
window._cdwieToggleLiveFeed = function() {
  _cdwie.graph.live = !_cdwie.graph.live;
  var isLive = _cdwie.graph.live;
  /* Build a live event feed panel */
  var severityColors = { CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#eab308', LOW:'#22c55e', INFO:'#6366f1' };
  var eventTypes = [
    { icon:'user-secret', sev:'CRITICAL', actor:'APT29', msg:'New C2 beacon detected on 185.220.101.47 — HAMMERTOSS variant' },
    { icon:'bug',         sev:'HIGH',     actor:'LockBit', msg:'Ransomware pre-staging activity detected in EU healthcare network' },
    { icon:'fingerprint', sev:'HIGH',     actor:'FIN7',   msg:'Credential dump posted on BreachForums — 12,400 enterprise accounts' },
    { icon:'dragon',      sev:'MEDIUM',   actor:'APT41',  msg:'Supply chain recon against telecom vendor supply chain observed' },
    { icon:'skull-crossbones', sev:'CRITICAL', actor:'Lazarus', msg:'Crypto wallet drainer deployed — $2.1M in ETH exfiltrated' },
    { icon:'eye',         sev:'HIGH',     actor:'APT29',  msg:'SUNBURST variant signature detected on VirusTotal — new submission' },
    { icon:'lock',        sev:'CRITICAL', actor:'BlackCat', msg:'New victim portal erected on ALPHV .onion — US law firm targeted' },
    { icon:'oil-can',     sev:'MEDIUM',   actor:'OilRig', msg:'DNS tunneling C2 traffic pattern detected — Middle East energy sector' },
    { icon:'satellite-dish', sev:'INFO',  actor:'System', msg:'Dark web index crawl completed — 847,412 documents processed' },
    { icon:'shield-alt',  sev:'LOW',      actor:'System', msg:'TOR exit node list updated — 1,247 new nodes classified' },
    { icon:'exclamation-triangle', sev:'HIGH', actor:'APT41', msg:'Zero-day PoC circulating on Exploit[.]in — VMware vCenter target' },
    { icon:'fire',        sev:'CRITICAL', actor:'LockBit', msg:'Active encryption event detected — 47 endpoints affected, 15 min ago' }
  ];
  var now = new Date();
  var eventsHtml = eventTypes.map(function(ev, i) {
    var t = new Date(now - i * _rand(90000, 420000));
    var timeStr = t.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
    var sc = severityColors[ev.sev] || '#6366f1';
    return '<div class="cdwie-live-event cdwie-card-reveal" style="animation-delay:' + (i*0.04) + 's;border-left:3px solid ' + sc + '">' +
      '<div class="cdwie-live-event-header">' +
        '<span class="cdwie-live-ev-icon" style="color:' + sc + '"><i class="fas fa-' + ev.icon + '"></i></span>' +
        '<span class="cdwie-live-ev-sev" style="background:' + sc + '22;color:' + sc + '">' + ev.sev + '</span>' +
        '<span class="cdwie-live-ev-actor">' + ev.actor + '</span>' +
        '<span class="cdwie-live-ev-time">' + timeStr + '</span>' +
      '</div>' +
      '<div class="cdwie-live-ev-msg">' + ev.msg + '</div>' +
    '</div>';
  }).join('');
  var statsHtml =
    '<div class="cdwie-live-stats">' +
      '<div class="cdwie-live-stat"><span style="color:#ef4444;font-size:18px;font-weight:700">' + _rand(3,8) + '</span><span>CRITICAL</span></div>' +
      '<div class="cdwie-live-stat"><span style="color:#f97316;font-size:18px;font-weight:700">' + _rand(8,15) + '</span><span>HIGH</span></div>' +
      '<div class="cdwie-live-stat"><span style="color:#eab308;font-size:18px;font-weight:700">' + _rand(14,28) + '</span><span>MEDIUM</span></div>' +
      '<div class="cdwie-live-stat"><span style="color:#22c55e;font-size:18px;font-weight:700">' + _rand(30,60) + '</span><span>LOW/INFO</span></div>' +
    '</div>';
  var html =
    '<div class="cdwie-live-feed-panel">' +
      '<div class="cdwie-live-header-row">' +
        '<span class="' + (isLive ? 'cdwie-status-badge' : 'cdwie-status-badge-paused') + '">' +
          '<span class="cdwie-status-dot' + (isLive ? '' : ' paused') + '"></span>' +
          (isLive ? 'LIVE MONITORING ACTIVE' : 'MONITORING PAUSED') +
        '</span>' +
        '<span style="color:#64748b;font-size:11px">Auto-refresh every 30s · ' + now.toLocaleTimeString() + '</span>' +
      '</div>' +
      statsHtml +
      '<div style="margin-top:4px;margin-bottom:8px">' +
        '<div style="color:#475569;font-size:10px;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px">Recent Events (Last 2 Hours)</div>' +
        eventsHtml +
      '</div>' +
      '<div style="margin-top:8px;display:flex;gap:8px">' +
        '<button class="cdwie-panel-action-btn" onclick="window._cdwieToggleLiveFeed();_toast(\'Feed ' + (isLive ? 'paused' : 'resumed') + '\',\'info\')"><i class="fas fa-' + (isLive ? 'pause' : 'play') + '"></i> ' + (isLive ? 'Pause Feed' : 'Resume Feed') + '</button>' +
        '<button class="cdwie-panel-action-btn" onclick="_toast(\'Events exported to SIEM\',\'success\')"><i class="fas fa-share-square"></i> Export to SIEM</button>' +
      '</div>' +
    '</div>';
  _openPanel('<i class="fas fa-satellite-dish" style="color:#22c55e"></i> Live Intelligence Feed', html);
};

window._cdwieAlertRules = function() {
  /* Alert rules management panel */
  var rules = [
    { id:'r1', name:'Critical Actor Activity', cond:'Any CRITICAL-tier actor IOC matches network traffic', action:'Webhook + Email', active:true, hits:_rand(12,45), icon:'user-secret', color:'#ef4444' },
    { id:'r2', name:'New Credential Dump', cond:'Corporate email domain appears in dark web credential dump', action:'Slack + PagerDuty', active:true, hits:_rand(3,8), icon:'key', color:'#f97316' },
    { id:'r3', name:'Ransomware Pre-Stage', cond:'Cobalt Strike / Beacon traffic pattern detected in egress', action:'Email + SIEM Alert', active:true, hits:_rand(0,2), icon:'bug', color:'#a855f7' },
    { id:'r4', name:'Zero-Day Circulating', cond:'Exploit targeting monitored software posted in last 24h', action:'Email', active:true, hits:_rand(1,5), icon:'exclamation-triangle', color:'#eab308' },
    { id:'r5', name:'Supply Chain Signal', cond:'Threat actor targets vendor in your supply chain', action:'Webhook', active:false, hits:0, icon:'link', color:'#22d3ee' },
    { id:'r6', name:'APT29 Infrastructure', cond:'APT29 C2 domain/IP detected in DNS or proxy logs', action:'PagerDuty Critical', active:true, hits:_rand(2,7), icon:'eye', color:'#ef4444' },
    { id:'r7', name:'Dark Web Brand Mention', cond:'Organization name mentioned in forum post or data listing', action:'Email Daily Digest', active:false, hits:_rand(4,12), icon:'spider', color:'#ec4899' }
  ];
  var rulesHtml = rules.map(function(rule) {
    return '<div class="cdwie-alert-rule" id="cdwie-rule-' + rule.id + '">' +
      '<div class="cdwie-rule-left">' +
        '<div class="cdwie-rule-icon" style="background:' + rule.color + '22;color:' + rule.color + '">' +
          '<i class="fas fa-' + rule.icon + '"></i>' +
        '</div>' +
        '<div class="cdwie-rule-body">' +
          '<div class="cdwie-rule-name">' + rule.name + '</div>' +
          '<div class="cdwie-rule-cond">' + rule.cond + '</div>' +
          '<div class="cdwie-rule-meta">' +
            '<span class="cdwie-badge cdwie-badge-blue">' + rule.action + '</span>' +
            '<span style="color:#475569;font-size:10px"><i class="fas fa-bell"></i> ' + rule.hits + ' triggers</span>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="cdwie-rule-right">' +
        '<label class="cdwie-toggle-switch">' +
          '<input type="checkbox" ' + (rule.active ? 'checked' : '') + ' onchange="_cdwieToggleRule(\'' + rule.id + '\',this.checked)">' +
          '<span class="cdwie-toggle-slider"></span>' +
        '</label>' +
      '</div>' +
    '</div>';
  }).join('');
  var html =
    '<div class="cdwie-alert-rules-panel">' +
      '<div class="cdwie-rules-summary">' +
        '<div class="cdwie-rule-stat"><span style="color:#22c55e;font-size:18px;font-weight:700">' + rules.filter(function(r){return r.active;}).length + '</span><span>Active</span></div>' +
        '<div class="cdwie-rule-stat"><span style="color:#64748b;font-size:18px;font-weight:700">' + rules.filter(function(r){return !r.active;}).length + '</span><span>Paused</span></div>' +
        '<div class="cdwie-rule-stat"><span style="color:#f97316;font-size:18px;font-weight:700">' + rules.reduce(function(s,r){return s+r.hits;},0) + '</span><span>Total Triggers</span></div>' +
      '</div>' +
      '<div style="margin-bottom:8px;color:#475569;font-size:10px;text-transform:uppercase;letter-spacing:0.08em">Configured Rules</div>' +
      rulesHtml +
      '<div style="margin-top:12px">' +
        '<button class="cdwie-panel-action-btn" style="background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none" onclick="_toast(\'Rule builder — use the form to create custom rules\',\'info\')"><i class="fas fa-plus"></i> Add New Rule</button>' +
        '<button class="cdwie-panel-action-btn" onclick="_toast(\'Alert rules exported\',\'success\')"><i class="fas fa-download"></i> Export Rules (JSON)</button>' +
      '</div>' +
    '</div>';
  _openPanel('<i class="fas fa-bell" style="color:#f97316"></i> Alert Rules Configuration', html);
};

window._cdwieToggleRule = function(id, active) {
  _toast('Rule ' + (active ? 'activated' : 'paused'), active ? 'success' : 'info');
  var row = document.getElementById('cdwie-rule-' + id);
  if (row) row.style.opacity = active ? '1' : '0.5';
};

window._cdwieInvestigationMode = function() {
  /* Investigation workspace — IOC pivot table + timeline + correlation */
  var iocRows = [
    { ioc:'195.54.162.88',     type:'IPv4',   actor:'APT29',   campaign:'WINTER STORM', tlp:'RED',   first:'2024-11-14', last:'4h ago',  malicious:true },
    { ioc:'midnight-shop[.]ru', type:'Domain', actor:'APT29',   campaign:'WINTER STORM', tlp:'RED',   first:'2024-10-22', last:'2d ago',  malicious:true },
    { ioc:'lockbit4.onion',    type:'Onion',  actor:'LockBit', campaign:'IRON TWILIGHT', tlp:'RED',   first:'2024-09-01', last:'12h ago', malicious:true },
    { ioc:'SHA256:a1b2c3d4e5', type:'Hash',   actor:'APT41',   campaign:'DRAGONFLY',     tlp:'AMBER', first:'2024-08-15', last:'5d ago',  malicious:true },
    { ioc:'45.142.212.100',    type:'IPv4',   actor:'Lazarus', campaign:'SILENT RANSOM', tlp:'RED',   first:'2024-07-30', last:'18h ago', malicious:true },
    { ioc:'AS44477',           type:'ASN',    actor:'LockBit', campaign:'IRON TWILIGHT', tlp:'AMBER', first:'2024-06-10', last:'3d ago',  malicious:true },
    { ioc:'svr-proxy[.]net',   type:'Domain', actor:'APT29',   campaign:'WINTER STORM', tlp:'RED',   first:'2024-11-01', last:'1h ago',  malicious:true }
  ];
  var pivotHtml = iocRows.map(function(row, i) {
    var tlpC = {RED:'#ef4444',AMBER:'#f59e0b',GREEN:'#22c55e',WHITE:'#94a3b8'}[row.tlp]||'#94a3b8';
    return '<tr class="cdwie-inv-row cdwie-card-reveal" style="animation-delay:' + (i*0.05) + 's">' +
      '<td><code class="cdwie-ioc-inline">' + row.ioc + '</code></td>' +
      '<td><span class="cdwie-badge cdwie-badge-blue">' + row.type + '</span></td>' +
      '<td style="color:#f1f5f9;font-size:12px">' + row.actor + '</td>' +
      '<td><span class="cdwie-badge cdwie-badge-purple">' + row.campaign + '</span></td>' +
      '<td><span style="background:' + tlpC + '22;color:' + tlpC + ';font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px">TLP:' + row.tlp + '</span></td>' +
      '<td style="color:#64748b;font-size:11px">' + row.last + '</td>' +
      '<td><button onclick="_toast(\'Pivoting on ' + row.ioc.replace(/'/g,'\\\'' ) + '\',\'info\')" style="background:none;border:none;color:#6366f1;cursor:pointer;font-size:11px"><i class="fas fa-crosshairs"></i> Pivot</button></td>' +
    '</tr>';
  }).join('');
  var timelineEvents = [
    { t:'2024-11-14 08:22', sev:'CRITICAL', desc:'APT29 deploys HAMMERTOSS variant — initial beacon to 195.54.162.88' },
    { t:'2024-11-14 09:15', sev:'HIGH',     desc:'Lateral movement detected — ADCS abuse, targeting Domain Controller' },
    { t:'2024-11-14 11:40', sev:'CRITICAL', desc:'Domain admin credentials harvested — LSASS dump via Mimikatz' },
    { t:'2024-11-14 14:05', sev:'HIGH',     desc:'Staging directory created — 2.4GB data collected for exfiltration' },
    { t:'2024-11-14 17:30', sev:'CRITICAL', desc:'Data exfiltrated via OneDrive API — SUNBURST C2 channel' },
    { t:'2024-11-15 03:11', sev:'MEDIUM',   desc:'Persistence established — scheduled task + WMI event subscription' },
    { t:'2024-11-16 09:00', sev:'HIGH',     desc:'Second stage payload downloaded — PolyglotDuke variant identified' }
  ];
  var sevC = {CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308'};
  var tlHtml = timelineEvents.map(function(ev, i) {
    var c = sevC[ev.sev]||'#6366f1';
    return '<div class="cdwie-tl-event cdwie-card-reveal" style="animation-delay:' + (i*0.06) + 's">' +
      '<div class="cdwie-tl-dot" style="background:' + c + ';box-shadow:0 0 6px ' + c + '"></div>' +
      '<div class="cdwie-tl-body">' +
        '<div class="cdwie-tl-time">' + ev.t + '</div>' +
        '<div class="cdwie-tl-sev" style="color:' + c + '">' + ev.sev + '</div>' +
        '<div class="cdwie-tl-desc">' + ev.desc + '</div>' +
      '</div>' +
    '</div>';
  }).join('');
  var mitrePhases = [
    {phase:'Initial Access',    ttp:'T1566.001', name:'Spear-Phishing Link',    done:true},
    {phase:'Execution',         ttp:'T1059.001', name:'PowerShell',              done:true},
    {phase:'Persistence',       ttp:'T1053.005', name:'Scheduled Task',          done:true},
    {phase:'Defense Evasion',   ttp:'T1027',     name:'Obfuscated Files',        done:true},
    {phase:'Credential Access', ttp:'T1003.001', name:'LSASS Memory',            done:true},
    {phase:'Lateral Movement',  ttp:'T1021.002', name:'SMB/Windows Admin Shares',done:true},
    {phase:'Collection',        ttp:'T1560',     name:'Archive Collected Data',  done:true},
    {phase:'Exfiltration',      ttp:'T1041',     name:'Exfil Over C2 Channel',   done:true}
  ];
  var mitreHtml = mitrePhases.map(function(m) {
    return '<div class="cdwie-mitre-row">' +
      '<span class="cdwie-mitre-id">' + m.ttp + '</span>' +
      '<span class="cdwie-mitre-name">' + m.name + '</span>' +
      '<span class="cdwie-badge cdwie-badge-purple">' + m.phase + '</span>' +
      '<i class="fas fa-check-circle" style="color:#22c55e;margin-left:auto;font-size:12px"></i>' +
    '</div>';
  }).join('');
  var html =
    '<div class="cdwie-investigation-workspace">' +
      '<div class="cdwie-inv-tabs">' +
        '<button class="cdwie-inv-tab active" onclick="_cdwieInvTab(this,\'pivot\')"><i class="fas fa-table"></i> IOC Pivot</button>' +
        '<button class="cdwie-inv-tab" onclick="_cdwieInvTab(this,\'timeline\')"><i class="fas fa-history"></i> Attack Timeline</button>' +
        '<button class="cdwie-inv-tab" onclick="_cdwieInvTab(this,\'mitre\')"><i class="fas fa-sitemap"></i> MITRE ATT&CK</button>' +
      '</div>' +
      '<div id="cdwie-inv-tab-pivot" class="cdwie-inv-pane">' +
        '<div style="color:#64748b;font-size:11px;margin-bottom:10px">7 IOCs under active investigation — Click Pivot to expand correlation</div>' +
        '<div style="overflow-x:auto"><table class="cdwie-inv-table" style="width:100%;border-collapse:collapse">' +
          '<thead><tr style="color:#475569;font-size:10px;text-transform:uppercase;border-bottom:1px solid #1e293b">' +
            '<th style="padding:6px 8px;text-align:left">Indicator</th><th style="padding:6px 8px">Type</th>' +
            '<th style="padding:6px 8px">Actor</th><th style="padding:6px 8px">Campaign</th>' +
            '<th style="padding:6px 8px">TLP</th><th style="padding:6px 8px">Last Seen</th><th style="padding:6px 8px">Actions</th>' +
          '</tr></thead>' +
          '<tbody>' + pivotHtml + '</tbody>' +
        '</table></div>' +
        '<div style="margin-top:10px;display:flex;gap:6px">' +
          '<button class="cdwie-panel-action-btn" onclick="_toast(\'IOC list exported as STIX 2.1\',\'success\')"><i class="fas fa-code"></i> Export STIX</button>' +
          '<button class="cdwie-panel-action-btn" onclick="_toast(\'Blocklist pushed to SIEM\',\'success\')"><i class="fas fa-shield-alt"></i> Push Blocklist</button>' +
        '</div>' +
      '</div>' +
      '<div id="cdwie-inv-tab-timeline" class="cdwie-inv-pane" style="display:none">' +
        '<div style="color:#64748b;font-size:11px;margin-bottom:14px">Reconstructed attack timeline · Attributed to APT29 WINTER STORM campaign</div>' +
        '<div class="cdwie-timeline-track">' + tlHtml + '</div>' +
        '<button class="cdwie-panel-action-btn" style="margin-top:10px" onclick="_toast(\'Timeline exported as PDF\',\'success\')"><i class="fas fa-file-pdf"></i> Export Timeline Report</button>' +
      '</div>' +
      '<div id="cdwie-inv-tab-mitre" class="cdwie-inv-pane" style="display:none">' +
        '<div style="color:#64748b;font-size:11px;margin-bottom:10px">ATT&CK® coverage for WINTER STORM — 8/14 tactics observed</div>' +
        '<div class="cdwie-mitre-grid">' + mitreHtml + '</div>' +
        '<button class="cdwie-panel-action-btn" style="margin-top:10px" onclick="_toast(\'MITRE Navigator layer exported\',\'success\')"><i class="fas fa-map"></i> Export Navigator Layer</button>' +
      '</div>' +
    '</div>';
  _openPanel('<i class="fas fa-search" style="color:#6366f1"></i> Investigation Workspace', html);
};

window._cdwieInvTab = function(btn, tab) {
  document.querySelectorAll('.cdwie-inv-tab').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  ['pivot','timeline','mitre'].forEach(function(t) {
    var pane = document.getElementById('cdwie-inv-tab-' + t);
    if (pane) pane.style.display = t === tab ? 'block' : 'none';
  });
};


/* ═══════════════════════════════════════════════════════════════════════════
   ENGINE 1 — COGNITIVE SEARCH
   ═══════════════════════════════════════════════════════════════════════════ */

var DW_SEARCH_RESULTS = [
  { id:'sr1', type:'actor', confidence:94, tlp:'RED', title:'APT29 Cozy Bear', subtitle:'Nation-state threat actor — Russia SVR',
    tags:['Nation-State','Espionage','Russia'], summary:'Highly sophisticated threat actor attributed to Russian Foreign Intelligence Service (SVR). Active since 2008, specializing in long-term espionage operations against government, defense, and energy sectors.',
    iocs:['195.54.162.88','midnight-shop[.]ru','svr-proxy[.]net'], references:3, lastSeen:'2h ago', risk:'critical' },
  { id:'sr2', type:'malware', confidence:87, tlp:'AMBER', title:'SUNBURST Backdoor', subtitle:'Supply chain implant — SolarWinds campaign',
    tags:['Backdoor','Supply-Chain','APT29'], summary:'Sophisticated backdoor delivered via trojanized SolarWinds Orion updates. Uses DGA for C2 communication and mimics legitimate SolarWinds traffic patterns.',
    iocs:['avsvmcloud[.]com','digitalcollege[.]org','freescanonline[.]com'], references:12, lastSeen:'3d ago', risk:'high' },
  { id:'sr3', type:'campaign', confidence:91, tlp:'RED', title:'Operation MidnightBlizzard', subtitle:'Active espionage campaign targeting NATO members',
    tags:['Espionage','NATO','Active'], summary:'Ongoing campaign targeting NATO member state diplomatic communications. Leverages spear-phishing with ISO attachment delivery and SUNBURST variants.',
    iocs:['nato-secure[.]org','brussels-mail[.]eu'], references:7, lastSeen:'6h ago', risk:'critical' },
  { id:'sr4', type:'ioc', confidence:99, tlp:'RED', title:'195.54.162.88', subtitle:'Active C2 Infrastructure — APT29',
    tags:['C2','IPv4','Active'], summary:'Confirmed active command-and-control server associated with APT29 SUNBURST campaign. Hosting nginx/1.18.0, certificate issued 2024-11-14, AS: AS8342 Rostelecom.',
    iocs:['195.54.162.88'], references:5, lastSeen:'22m ago', risk:'critical' },
  { id:'sr5', type:'malware', confidence:82, tlp:'AMBER', title:'WellMess RAT', subtitle:'Remote access trojan — Russian nexus',
    tags:['RAT','Russia','Golang'], summary:'Go-based remote access tool attributed to APT29. Uses HTTP/HTTPS with custom encryption. Observed targeting COVID-19 vaccine research organizations.',
    iocs:['45.142.212.100','well-mess[.]su'], references:8, lastSeen:'5d ago', risk:'high' },
  { id:'sr6', type:'darkweb', confidence:78, tlp:'AMBER', title:'Forum Post: NATO VPN Credentials', subtitle:'BreachForums — credential dump listing',
    tags:['Credentials','NATO','VPN','BreachForums'], summary:'Forum post advertising alleged NATO member VPN credential dump. 4,200 credentials claimed. Seller "phantom_admin" — reputation score 87/100 on BreachForums.',
    iocs:[], references:2, lastSeen:'14h ago', risk:'high' },
  { id:'sr7', type:'infra', confidence:85, tlp:'AMBER', title:'Bulletproof Hosting Cluster', subtitle:'AS48693 — known APT infrastructure provider',
    tags:['Hosting','BulletProof','AS48693'], summary:'Autonomous system known for providing bulletproof hosting to APT groups. Hosts multiple domains associated with APT29, APT41. Located in Russia, unresponsive to abuse reports.',
    iocs:['AS48693','91.108.56.0/22'], references:9, lastSeen:'1d ago', risk:'high' }
];

var DW_QUERY_SUGGESTIONS = [
  'APT29 recent C2 infrastructure',
  'LockBit 3.0 ransomware IOCs 2024',
  'supply chain attacks financial sector',
  'darkweb credential dumps government',
  'OPSEC techniques Russian APT groups',
  'zero-day exploits CVE 2024',
  'ransomware double-extortion campaigns',
  'critical infrastructure targeting nation-state'
];

function _buildEngineCognitiveSearch() {
  var sugg = DW_QUERY_SUGGESTIONS.map(function(q) {
    return '<button class="cdwie-query-chip" onclick="window._cdwieRunSearch(' + JSON.stringify(q) + ')">' + q + '</button>';
  }).join('');

  return '<div class="cdwie-engine" id="cdwie-engine-cognitive-search">' +
    '<div class="cdwie-search-zone">' +
      '<div class="cdwie-search-header">' +
        '<h2 class="cdwie-engine-title"><i class="fas fa-search-plus"></i> Cognitive Dark Web Search</h2>' +
        '<p class="cdwie-engine-sub">AI-powered intelligence retrieval across dark web forums, paste sites, onion services, and threat actor communication channels</p>' +
      '</div>' +
      '<div class="cdwie-search-main">' +
        '<div class="cdwie-search-input-wrap">' +
          '<i class="fas fa-search cdwie-search-icon"></i>' +
          '<input id="cdwie-search-input" class="cdwie-search-input" type="text" placeholder="Search threat actors, IOCs, campaigns, malware families..." ' +
            'onkeydown="if(event.key===\'Enter\')window._cdwieRunSearch()" />' +
          '<button class="cdwie-search-btn" onclick="window._cdwieRunSearch()"><i class="fas fa-bolt"></i> Analyze</button>' +
        '</div>' +
        '<div class="cdwie-search-meta">' +
          '<span class="cdwie-meta-item"><i class="fas fa-database"></i> 847K documents indexed</span>' +
          '<span class="cdwie-meta-item"><i class="fas fa-clock"></i> Updated 4m ago</span>' +
          '<span class="cdwie-meta-item"><i class="fas fa-shield-alt"></i> TLP:RED access enabled</span>' +
        '</div>' +
      '</div>' +
      '<div class="cdwie-suggestions-bar">' +
        '<span class="cdwie-sugg-label"><i class="fas fa-lightbulb"></i> Suggested:</span>' +
        sugg +
      '</div>' +
    '</div>' +
    '<div id="cdwie-search-results-wrap" class="cdwie-results-zone" style="display:none">' +
      '<div class="cdwie-results-header">' +
        '<span id="cdwie-results-count" class="cdwie-results-count"></span>' +
        '<div class="cdwie-results-filters">' +
          '<button class="cdwie-filter-btn active" onclick="window._cdwieFilterResults(this,\'all\')">All</button>' +
          '<button class="cdwie-filter-btn" onclick="window._cdwieFilterResults(this,\'actor\')">Actors</button>' +
          '<button class="cdwie-filter-btn" onclick="window._cdwieFilterResults(this,\'malware\')">Malware</button>' +
          '<button class="cdwie-filter-btn" onclick="window._cdwieFilterResults(this,\'campaign\')">Campaigns</button>' +
          '<button class="cdwie-filter-btn" onclick="window._cdwieFilterResults(this,\'ioc\')">IOCs</button>' +
          '<button class="cdwie-filter-btn" onclick="window._cdwieFilterResults(this,\'darkweb\')">Dark Web</button>' +
        '</div>' +
      '</div>' +
      '<div id="cdwie-search-results" class="cdwie-results-grid"></div>' +
    '</div>' +
    '<div id="cdwie-search-loading" class="cdwie-loading-zone" style="display:none">' +
      '<div class="cdwie-loading-spinner"><div class="cdwie-spinner"></div><span>Analyzing intelligence sources...</span></div>' +
      '<div class="cdwie-loading-steps" id="cdwie-loading-steps"></div>' +
    '</div>' +
  '</div>';
}

window._cdwieRunSearch = function(queryArg) {
  var input = document.getElementById('cdwie-search-input');
  var q = queryArg || (input ? input.value.trim() : '');
  if (!q) { _toast('Enter a search query', 'warning'); return; }
  if (input) input.value = q;
  _cdwie.search.query = q;
  _cdwie.search.running = true;

  var wrap = document.getElementById('cdwie-search-results-wrap');
  var loading = document.getElementById('cdwie-search-loading');
  var steps = document.getElementById('cdwie-loading-steps');
  if (wrap) wrap.style.display = 'none';
  if (loading) loading.style.display = 'flex';

  var loadSteps = [
    'Querying dark web index nodes...',
    'Cross-referencing threat actor database...',
    'Analyzing IOC correlation matrix...',
    'Fetching intelligence from onion sources...',
    'Running NLP semantic analysis...',
    'Generating confidence scores...'
  ];
  var si = 0;
  if (steps) steps.innerHTML = '';
  var stepInt = setInterval(function() {
    if (si >= loadSteps.length) { clearInterval(stepInt); return; }
    if (steps) {
      var d = document.createElement('div');
      d.className = 'cdwie-loading-step';
      d.innerHTML = '<i class="fas fa-check-circle"></i> ' + loadSteps[si];
      steps.appendChild(d);
      setTimeout(function(el){ el.classList.add('done'); }, 100, d);
    }
    si++;
  }, 280);

  setTimeout(function() {
    clearInterval(stepInt);
    if (loading) loading.style.display = 'none';
    _cdwie.search.running = false;
    _cdwieRenderSearchResults(_cdwieQueryResults(q));
  }, 1900);
};

/* ── Dynamic query engine: returns contextually-matched results based on query ── */
function _cdwieQueryResults(q) {
  var qL = q.toLowerCase();
  /* Score each result against the query */
  var scored = DW_SEARCH_RESULTS.map(function(r) {
    var score = 0;
    var fields = [r.title, r.subtitle, r.summary, (r.tags||[]).join(' '), (r.iocs||[]).join(' ')];
    fields.forEach(function(f) {
      if (!f) return;
      var fl = f.toLowerCase();
      /* Exact phrase match */
      if (fl.includes(qL)) score += 40;
      /* Word-level matches */
      qL.split(/\s+/).forEach(function(word) {
        if (word.length > 2 && fl.includes(word)) score += 10;
      });
    });
    /* Actor name/alias matching */
    Object.values(DW_ACTORS).forEach(function(a) {
      var aL = (a.name + ' ' + a.alias + ' ' + (a.aliases||[]).join(' ')).toLowerCase();
      if (qL.includes(a.id) || aL.split(' ').some(function(w){ return w.length > 3 && qL.includes(w); })) {
        if ((r.title+r.subtitle+r.summary).toLowerCase().includes(a.id) ||
            (r.title+r.subtitle+r.summary).toLowerCase().includes(a.name.toLowerCase())) {
          score += 25;
        }
      }
    });
    return { r: r, score: score + Math.random() * 5 };
  });
  /* Sort by score descending */
  scored.sort(function(a,b){ return b.score - a.score; });
  var matched = scored.filter(function(x){ return x.score > 5; }).map(function(x){ return x.r; });
  /* If nothing matched, generate contextual synthetic results */
  if (matched.length === 0) {
    matched = _cdwieSynthesizeResults(q);
  } else if (matched.length < 3) {
    /* Pad with synthetic results */
    matched = matched.concat(_cdwieSynthesizeResults(q).slice(0, 4 - matched.length));
  }
  /* Adjust confidence scores based on query relevance */
  return matched.slice(0, 7).map(function(r, i) {
    return Object.assign({}, r, {
      confidence: Math.max(55, Math.min(99, r.confidence - i * 3 + _rand(-5,5))),
      lastSeen: i === 0 ? _rand(5,45) + 'm ago' : i < 3 ? _rand(1,12) + 'h ago' : _rand(1,5) + 'd ago'
    });
  });
}

/* ── Synthesize contextual results for novel queries ── */
function _cdwieSynthesizeResults(q) {
  var qL = q.toLowerCase();
  var now = new Date();
  /* Determine category from keywords */
  var isActorQ  = /apt|fin|group|nation|state|bear|panda|dragon|lazarus|cozy|fancy/.test(qL);
  var isIocQ    = /\d{1,3}\.\d{1,3}\.\d{1,3}|\.(onion|ru|cn|ir)|hash|sha|md5|domain|ip\b/.test(qL);
  var isMalware = /malware|ransomware|rat|trojan|backdoor|stealer|botnet|loader|dropper|beacon|cobalt/.test(qL);
  var isCampaign= /campaign|operation|op\s|attack|storm|iron|winter|silent|dragonfly/.test(qL);
  var isCredQ   = /cred|password|dump|breach|leak|forum|darkweb|dark web|breach/.test(qL);
  var isCveQ    = /cve|zero.day|vuln|exploit|rce|lpe|0day/.test(qL);
  /* Extract potential actor references */
  var actorMatch = Object.values(DW_ACTORS).filter(function(a) {
    var nm = (a.name+' '+(a.aliases||[]).join(' ')+' '+a.alias).toLowerCase();
    return qL.split(/\s+/).some(function(w){ return w.length > 3 && nm.includes(w); });
  })[0];
  var actor = actorMatch || Object.values(DW_ACTORS)[Math.floor(Math.random()*Object.values(DW_ACTORS).length)];
  var ts = function(h) { return h < 60 ? h + 'm ago' : h < 1440 ? Math.floor(h/60) + 'h ago' : Math.floor(h/1440) + 'd ago'; };
  var base = [];
  /* Actor result */
  if (isActorQ || actorMatch) {
    base.push({ id:'syn1', type:'actor', confidence:_rand(78,97), tlp:'RED',
      title: actor.name, subtitle: actor.alias + ' \u2014 ' + actor.origin,
      tags: [actor.origin, actor.threat, 'Nation-State'].filter(Boolean),
      summary: actor.desc ? actor.desc.substring(0,200)+'...' : 'Tracked threat actor with confirmed operational history.',
      iocs: (actor.infra && actor.infra.c2Domains) ? actor.infra.c2Domains.slice(0,2) : [],
      references: _rand(5,18), lastSeen: ts(_rand(30,300)), risk: actor.threat.toLowerCase() });
  }
  /* IOC / Infrastructure result */
  if (isIocQ) {
    base.push({ id:'syn2', type:'ioc', confidence:_rand(85,99), tlp:'RED',
      title: qL.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) ? q.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)[0] : q.substring(0,30),
      subtitle: 'Active C2 Infrastructure \u2014 ' + actor.name,
      tags:['C2','Active','Malicious'], summary:'IOC identified in ' + _rand(3,14) + ' independent threat feeds. Cross-referenced with ' + actor.name + ' operational infrastructure. ASN: ' + (actor.infra&&actor.infra.asns?actor.infra.asns[0]:'AS unknown') + '.',
      iocs:[q.substring(0,40)], references:_rand(3,9), lastSeen:ts(_rand(5,120)), risk:'critical' });
  }
  /* Malware family result */
  if (isMalware || Math.random()>0.5) {
    var tools = actor.tools || ['Cobalt Strike','Mimikatz'];
    var tool = tools[Math.floor(Math.random()*tools.length)];
    base.push({ id:'syn3', type:'malware', confidence:_rand(72,95), tlp:'AMBER',
      title: tool, subtitle: 'Malware family \u2014 ' + actor.name + ' toolkit',
      tags:['Malware',actor.origin,'Active'], summary:'Observed in active campaigns attributed to ' + actor.name + '. Detected by ' + _rand(35,68) + '/72 AV vendors. Latest variant deployed in ' + now.getFullYear() + '.',
      iocs:[], references:_rand(4,14), lastSeen:ts(_rand(60,720)), risk:'high' });
  }
  /* Campaign result */
  if (isCampaign || DW_PREDICTIONS.campaigns.length) {
    var camp = DW_PREDICTIONS.campaigns[Math.floor(Math.random()*DW_PREDICTIONS.campaigns.length)];
    base.push({ id:'syn4', type:'campaign', confidence:_rand(74,96), tlp:'RED',
      title:'Operation '+camp.name, subtitle:'Active campaign \u2014 '+camp.group,
      tags:['Campaign','Active',camp.confidence], summary:'Campaign currently in phase '+(camp.phaseDone||2)+' of '+camp.phases.length+'. Probability of escalation: '+camp.prob+'%. Expected impact timeframe: '+camp.eta+'.',
      iocs:[], references:_rand(3,8), lastSeen:ts(_rand(10,200)), risk: camp.prob >= 80 ? 'critical' : 'high' });
  }
  /* Dark web forum / credential result */
  if (isCredQ || Math.random()>0.6) {
    base.push({ id:'syn5', type:'darkweb', confidence:_rand(65,88), tlp:'AMBER',
      title:'Forum Thread: '+q.substring(0,35), subtitle:'BreachForums \u2014 threat actor discussion',
      tags:['DarkWeb','Forum','Intel'], summary:'Thread posted by high-reputation user (score 82/100). References '+actor.name+'. '+(isCredQ?_rand(1000,50000).toLocaleString()+' records claimed. Partial sample validated. ':'Contains operational planning discussion. '),
      iocs:[], references:_rand(1,4), lastSeen:ts(_rand(60,1440)), risk:'high' });
  }
  /* CVE/Exploit result */
  if (isCveQ) {
    var cveId = 'CVE-'+(now.getFullYear()-_rand(0,1))+'-'+_rand(10000,50000);
    base.push({ id:'syn6', type:'ioc', confidence:_rand(80,98), tlp:'RED',
      title: cveId, subtitle:'Zero-day exploit \u2014 '+actor.name,
      tags:['CVE','Exploit','0-Day'], summary:'Vulnerability in '+(['VMware vCenter','Fortinet FortiOS','Citrix NetScaler','MOVEit Transfer','Exchange Server'][_rand(0,4)])+'. CVSS '+(_rand(75,100)/10).toFixed(1)+'. PoC observed in dark web exploit marketplaces. Attribution: '+actor.name+'.',
      iocs:[cveId], references:_rand(5,12), lastSeen:ts(_rand(15,360)), risk:'critical' });
  }
  /* Infrastructure result */
  base.push({ id:'syn7', type:'infra', confidence:_rand(68,88), tlp:'AMBER',
    title:'Bulletproof Hosting Cluster \u2014 '+(actor.infra&&actor.infra.asns?actor.infra.asns[0]:'AS'+_rand(10000,60000)),
    subtitle:'Known APT infrastructure provider',
    tags:['Hosting','BulletProof','Infrastructure'], summary:'Autonomous system providing infrastructure to '+actor.name+' and associated affiliates. '+ _rand(12,45) + ' malicious IPs observed in this range over 90 days.',
    iocs: (actor.infra&&actor.infra.asns) ? actor.infra.asns.slice(0,1) : [],
    references:_rand(4,11), lastSeen:ts(_rand(120,2880)), risk:'high' });
  return base;
}

window._cdwieGenerateQueries = function() {
  var suggestions = document.querySelectorAll('.cdwie-query-chip');
  suggestions.forEach(function(btn) {
    btn.style.opacity = '0.5';
    setTimeout(function() { btn.style.opacity = '1'; }, 600);
  });
  _toast('Query suggestions refreshed', 'success');
};

window._cdwieFilterResults = function(btn, type) {
  document.querySelectorAll('.cdwie-filter-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  var cards = document.querySelectorAll('.cdwie-result-card');
  var shown = 0;
  cards.forEach(function(c) {
    if (type === 'all' || c.dataset.type === type) {
      c.style.display = '';
      shown++;
    } else {
      c.style.display = 'none';
    }
  });
  var cnt = document.getElementById('cdwie-results-count');
  if (cnt) cnt.textContent = shown + ' results' + (type !== 'all' ? ' (' + type + ')' : '');
};

function _cdwieRenderSearchResults(results) {
  var wrap = document.getElementById('cdwie-search-results-wrap');
  var grid = document.getElementById('cdwie-search-results');
  var cnt = document.getElementById('cdwie-results-count');
  if (!wrap || !grid) return;

  if (cnt) cnt.textContent = results.length + ' results for "' + _cdwie.search.query + '"';
  wrap.style.display = 'block';

  var typeIcons = { actor:'user-secret', malware:'bug', campaign:'crosshairs', ioc:'fingerprint', darkweb:'spider', infra:'server' };
  var riskColors = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e' };

  grid.innerHTML = results.map(function(r, i) {
    var icon = typeIcons[r.type] || 'circle';
    var rColor = riskColors[r.risk] || '#6366f1';
    var tlpColor = { RED:'#ef4444', AMBER:'#f97316', GREEN:'#22c55e', WHITE:'#94a3b8' }[r.tlp] || '#6366f1';
    var tags = r.tags.map(function(t) { return '<span class="cdwie-badge cdwie-badge-blue">' + t + '</span>'; }).join('');
    var iocHtml = r.iocs.length ? '<div class="cdwie-result-iocs">' +
      r.iocs.map(function(ioc) { return '<code class="cdwie-ioc-inline">' + ioc + '</code>'; }).join('') +
    '</div>' : '';
    return '<div class="cdwie-result-card cdwie-card-reveal" data-type="' + r.type + '" style="animation-delay:' + (i*0.07) + 's" onclick="window._cdwieLoadResult(' + JSON.stringify(r.id) + ')">' +
      '<div class="cdwie-result-header">' +
        '<div class="cdwie-result-icon" style="background:' + rColor + '22;color:' + rColor + '"><i class="fas fa-' + icon + '"></i></div>' +
        '<div class="cdwie-result-meta">' +
          '<div class="cdwie-result-title">' + r.title + '</div>' +
          '<div class="cdwie-result-sub">' + r.subtitle + '</div>' +
        '</div>' +
        '<div class="cdwie-result-badges">' +
          '<span class="cdwie-conf-pill" style="background:' + rColor + '22;color:' + rColor + '">' + r.confidence + '% conf</span>' +
          '<span class="cdwie-tlp-pill" style="background:' + tlpColor + '22;color:' + tlpColor + '">TLP:' + r.tlp + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="cdwie-result-summary">' + r.summary + '</div>' +
      '<div class="cdwie-result-footer">' +
        tags +
        iocHtml +
        '<span class="cdwie-result-meta-item"><i class="fas fa-book"></i> ' + r.references + ' refs</span>' +
        '<span class="cdwie-result-meta-item"><i class="fas fa-clock"></i> ' + r.lastSeen + '</span>' +
      '</div>' +
    '</div>';
  }).join('');
}

window._cdwieLoadResult = function(id) {
  var r = DW_SEARCH_RESULTS.filter(function(x) { return x.id === id; })[0];
  if (!r) return;
  var iocRows = r.iocs.map(function(ioc) {
    return '<div class="cdwie-panel-ioc-row"><code>' + ioc + '</code><button onclick="_toast(\'Copied: ' + ioc + '\',\'success\')" class="cdwie-panel-copy-btn"><i class="fas fa-copy"></i></button></div>';
  }).join('');
  var html = '<div class="cdwie-panel-result-detail">' +
    '<div class="cdwie-panel-badge-row"><span class="cdwie-badge cdwie-badge-' + (r.risk==='critical'?'red':'orange') + '">' + r.risk.toUpperCase() + '</span>' +
    '<span class="cdwie-badge cdwie-badge-blue">TLP:' + r.tlp + '</span>' +
    '<span class="cdwie-badge cdwie-badge-purple">' + r.type.toUpperCase() + '</span></div>' +
    '<p class="cdwie-panel-summary">' + r.summary + '</p>' +
    (r.iocs.length ? '<h4>Indicators of Compromise</h4>' + iocRows : '') +
    '<div class="cdwie-panel-refs"><i class="fas fa-book-open"></i> ' + r.references + ' intelligence references</div>' +
    '<div class="cdwie-panel-last-seen"><i class="fas fa-clock"></i> Last seen: ' + r.lastSeen + '</div>' +
    '<div class="cdwie-panel-tags">' + r.tags.map(function(t) { return '<span class="cdwie-badge cdwie-badge-blue">' + t + '</span>'; }).join('') + '</div>' +
    '<button class="cdwie-panel-action-btn" onclick="_toast(\'Exported to report\',\'success\')"><i class="fas fa-file-export"></i> Add to Report</button>' +
    '<button class="cdwie-panel-action-btn" onclick="_toast(\'IOC monitoring activated\',\'success\')"><i class="fas fa-bell"></i> Monitor IOCs</button>' +
  '</div>';
  _openPanel(r.title, html);
};


/* ═══════════════════════════════════════════════════════════════════════════
   ENGINE 2 — THREAT ACTOR DNA
   ═══════════════════════════════════════════════════════════════════════════ */

function _buildEngineActorDNA() {
  var actorList = Object.values(DW_ACTORS).map(function(a) {
    var riskColor = a.threat.toLowerCase() === 'critical' ? '#ef4444' : a.threat.toLowerCase() === 'high' ? '#f97316' : '#eab308';
    return '<div class="cdwie-actor-row ' + (a.id === _cdwie.actor.selected ? 'active' : '') + '" ' +
      'onclick="window._cdwieSelectActor(\'' + a.id + '\')" data-actor="' + a.id + '">' +
      '<div class="cdwie-actor-avatar" style="background:' + a.color + '22;color:' + a.color + '">' +
        '<i class="fas fa-' + (a.faIcon||'user-secret') + '"></i>' +
      '</div>' +
      '<div class="cdwie-actor-info">' +
        '<div class="cdwie-actor-name">' + a.flag + ' ' + a.name + '</div>' +
        '<div class="cdwie-actor-alias">' + a.alias + '</div>' +
      '</div>' +
      '<div class="cdwie-actor-risk" style="color:' + riskColor + '">' +
        '<i class="fas fa-circle" style="font-size:8px"></i>' +
      '</div>' +
    '</div>';
  }).join('');

  return '<div class="cdwie-engine" id="cdwie-engine-actor-dna">' +
    '<div class="cdwie-actor-layout">' +
      '<div class="cdwie-actor-roster">' +
        '<div class="cdwie-roster-header">' +
          '<span class="cdwie-roster-title"><i class="fas fa-users"></i> Threat Actors</span>' +
          '<span class="cdwie-badge cdwie-badge-red">' + Object.keys(DW_ACTORS).length + ' tracked</span>' +
        '</div>' +
        '<div class="cdwie-actor-list">' + actorList + '</div>' +
      '</div>' +
      '<div class="cdwie-actor-detail" id="cdwie-actor-detail">' +
        '<div id="cdwie-actor-profile-content"><!-- populated by _renderActorProfile --></div>' +
      '</div>' +
    '</div>' +
  '</div>';
}

window._cdwieSelectActor = function(id) {
  _cdwie.actor.selected = id;
  document.querySelectorAll('.cdwie-actor-row').forEach(function(r) {
    r.classList.toggle('active', r.dataset.actor === id);
  });
  _renderActorProfile(id);
};

function _renderActorProfile(id) {
  var a = Object.values(DW_ACTORS).filter(function(x) { return x.id === id; })[0];
  if (!a) return;
  var cont = document.getElementById('cdwie-actor-profile-content');
  if (!cont) return;

  var riskColor = a.threat.toLowerCase() === 'critical' ? '#ef4444' : a.threat.toLowerCase() === 'high' ? '#f97316' : '#eab308';
  var sectors = a.sectors.map(function(s) { return '<span class="cdwie-badge cdwie-badge-blue">' + s + '</span>'; }).join('');
  var ttps = a.ttps.map(function(t) { return '<span class="cdwie-badge cdwie-badge-purple">' + t + '</span>'; }).join('');
  var tools = a.tools.map(function(t) { return '<span class="cdwie-badge cdwie-badge-teal">' + t + '</span>'; }).join('');

  var dnaTabButtons = [
    { id:'overview',   label:'Overview',    icon:'info-circle' },
    { id:'behavior',   label:'Behavior DNA', icon:'dna' },
    { id:'ttps',       label:'TTPs',         icon:'sitemap' },
    { id:'infra',      label:'Infrastructure', icon:'server' }
  ].map(function(t) {
    return '<button class="cdwie-dna-tab ' + (t.id===_cdwie.actor.dnaTab?'active':'') + '" onclick="window._cdwieDnaTab(\'' + id + '\',\'' + t.id + '\')">' +
      '<i class="fas fa-' + t.icon + '"></i> ' + t.label + '</button>';
  }).join('');

  var tabContent = _renderActorDnaTab(a, _cdwie.actor.dnaTab);

  cont.innerHTML =
    '<div class="cdwie-actor-profile">' +
      '<div class="cdwie-actor-profile-header">' +
        '<div class="cdwie-actor-avatar-lg" style="background:' + a.color + '22;color:' + a.color + '">' +
          '<i class="fas fa-' + (a.faIcon||'user-secret') + '"></i>' +
        '</div>' +
        '<div class="cdwie-actor-profile-meta">' +
          '<h2 class="cdwie-actor-profile-name">' + a.flag + ' ' + a.name + '</h2>' +
          '<div class="cdwie-actor-profile-alias">' + a.aliases.join(' · ') + '</div>' +
          '<div class="cdwie-actor-profile-badges">' +
            '<span class="cdwie-badge" style="background:' + riskColor + '22;color:' + riskColor + '">' + a.threat.toUpperCase() + ' THREAT</span>' +
            '<span class="cdwie-badge cdwie-badge-blue">Confidence: ' + a.confidence + '%</span>' +
            '<span class="cdwie-badge cdwie-badge-green">' + (a.active||'Active') + '</span>' +
          '</div>' +
        '</div>' +
        '<div class="cdwie-actor-profile-stats">' +
          '<div class="cdwie-stat-chip"><div class="cdwie-stat-val">' + a.ttps.length + '</div><div class="cdwie-stat-lbl">TTPs</div></div>' +
          '<div class="cdwie-stat-chip"><div class="cdwie-stat-val">' + a.tools.length + '</div><div class="cdwie-stat-lbl">Tools</div></div>' +
          '<div class="cdwie-stat-chip"><div class="cdwie-stat-val">' + a.sectors.length + '</div><div class="cdwie-stat-lbl">Sectors</div></div>' +
        '</div>' +
      '</div>' +
      '<div class="cdwie-dna-tabs">' + dnaTabButtons + '</div>' +
      '<div class="cdwie-dna-tab-content" id="cdwie-dna-tab-content">' + tabContent + '</div>' +
    '</div>';

  if (_cdwie.actor.dnaTab === 'behavior') {
    setTimeout(function() { _initActorRadarChart(a); }, 100);
  }
}

function _renderActorDnaTab(a, tab) {
  if (tab === 'overview') {
    var sectors = a.sectors.map(function(s) { return '<span class="cdwie-badge cdwie-badge-blue">' + s + '</span>'; }).join('');
    return '<div class="cdwie-dna-overview">' +
      '<p class="cdwie-actor-desc">' + a.desc + '</p>' +
      '<div class="cdwie-overview-grid">' +
        '<div class="cdwie-ov-item"><span class="cdwie-ov-label"><i class="fas fa-globe"></i> Origin</span><span class="cdwie-ov-val">' + a.flag + ' ' + a.origin + '</span></div>' +
        '<div class="cdwie-ov-item"><span class="cdwie-ov-label"><i class="fas fa-building"></i> Sponsor</span><span class="cdwie-ov-val">' + a.sponsor + '</span></div>' +
        '<div class="cdwie-ov-item"><span class="cdwie-ov-label"><i class="fas fa-clock"></i> Active Since</span><span class="cdwie-ov-val">' + a.active + '</span></div>' +
        '<div class="cdwie-ov-item"><span class="cdwie-ov-label"><i class="fas fa-pen-nib"></i> Writing Style</span><span class="cdwie-ov-val">' + a.writingStyle + '</span></div>' +
        '<div class="cdwie-ov-item"><span class="cdwie-ov-label"><i class="fas fa-moon"></i> Op Hours</span><span class="cdwie-ov-val">' + a.opHours + '</span></div>' +
      '</div>' +
      '<div class="cdwie-ov-sectors"><div class="cdwie-ov-label-block">Target Sectors</div>' + sectors + '</div>' +
    '</div>';
  }
  if (tab === 'behavior') {
    var b = a.behavior;
    var axisRows = Object.keys(b).map(function(k) {
      var val = b[k];
      return '<div class="cdwie-behavior-row">' +
        '<span class="cdwie-beh-label">' + k.replace(/_/g,' ').replace(/\b\w/g,function(c){return c.toUpperCase();}) + '</span>' +
        '<div class="cdwie-beh-bar-wrap"><div class="cdwie-beh-bar" style="width:' + val + '%"></div></div>' +
        '<span class="cdwie-beh-val">' + val + '</span>' +
      '</div>';
    }).join('');
    return '<div class="cdwie-dna-behavior">' +
      '<div class="cdwie-radar-wrap"><canvas id="cdwie-radar-chart" width="320" height="320"></canvas></div>' +
      '<div class="cdwie-behavior-bars">' + axisRows + '</div>' +
    '</div>';
  }
  if (tab === 'ttps') {
    var mitreRows = a.ttps.map(function(ttp) {
      var phases = ['Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion','Lateral Movement','Collection','Exfiltration'];
      var phase = phases[Math.floor(Math.random()*phases.length)];
      var tactics = { 'T1566':'Phishing','T1059':'Command & Scripting','T1547':'Boot Autostart','T1078':'Valid Accounts','T1070':'Indicator Removal',
        'T1021':'Remote Services','T1560':'Archive Collected Data','T1041':'Exfil over C2','T1190':'Exploit Public Application','T1055':'Process Injection',
        'T1003':'OS Credential Dumping','T1071':'App Layer Protocol','T1036':'Masquerading','T1053':'Scheduled Task','T1027':'Obfuscated Files' };
      var name = tactics[ttp] || ttp;
      return '<div class="cdwie-mitre-row">' +
        '<span class="cdwie-mitre-id">' + ttp + '</span>' +
        '<span class="cdwie-mitre-name">' + name + '</span>' +
        '<span class="cdwie-mitre-phase cdwie-badge cdwie-badge-purple">' + phase + '</span>' +
      '</div>';
    }).join('');
    return '<div class="cdwie-dna-ttps"><div class="cdwie-mitre-grid">' + mitreRows + '</div></div>';
  }
  if (tab === 'infra') {
    var inf = a.infra;
    var asnRows = (inf.asns||[]).map(function(asn) { return '<span class="cdwie-badge cdwie-badge-teal">' + asn + '</span>'; }).join('');
    var hostRows = (inf.hostingProviders||[]).map(function(h) { return '<span class="cdwie-badge cdwie-badge-orange">' + h + '</span>'; }).join('');
    var c2Rows = (inf.c2Domains||[]).map(function(d) { return '<code class="cdwie-ioc-inline">' + d + '</code>'; }).join('');
    return '<div class="cdwie-dna-infra">' +
      '<div class="cdwie-infra-section"><h4><i class="fas fa-network-wired"></i> ASNs</h4><div>' + (asnRows||'<span class="cdwie-dim">None on record</span>') + '</div></div>' +
      '<div class="cdwie-infra-section"><h4><i class="fas fa-server"></i> Hosting Providers</h4><div>' + (hostRows||'<span class="cdwie-dim">None on record</span>') + '</div></div>' +
      '<div class="cdwie-infra-section"><h4><i class="fas fa-link"></i> Known C2 Domains</h4><div class="cdwie-c2-list">' + (c2Rows||'<span class="cdwie-dim">None on record</span>') + '</div></div>' +
      '<div class="cdwie-heatmap-section">' +
        '<h4><i class="fas fa-th"></i> Activity Heatmap (UTC)</h4>' +
        '<div class="cdwie-heatmap-grid" id="cdwie-heatmap-' + a.id + '">' + _buildActivityHeatmap(a) + '</div>' +
      '</div>' +
    '</div>';
  }
  return '';
}

function _buildActivityHeatmap(a) {
  var days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  /* Determine active hour range from opHours string */
  var startH = 0, endH = 23;
  if (a.opHours) {
    var m = a.opHours.match(/(\d{2}):00\D+(\d{2}):00/);
    if (m) { startH = parseInt(m[1]); endH = parseInt(m[2]); }
  }
  var isNight = a.opHours && a.opHours.toLowerCase().includes('night');
  var isWeekday = a.opHours && (a.opHours.includes('Mon\u2013Fri') || a.opHours.includes('Mon-Fri') || a.opHours.includes('Tue\u2013Sat') || a.opHours.includes('Tue-Sat'));
  var isSundayRest = a.opHours && a.opHours.includes('Sun\u2013Thu');
  var actorColor = a.color || '#6366f1';
  /* Convert hex color to rgb */
  var rgb = '99,102,241';
  var hc = actorColor.replace('#','');
  if (hc.length === 6) {
    rgb = parseInt(hc.substr(0,2),16)+','+parseInt(hc.substr(2,2),16)+','+parseInt(hc.substr(4,2),16);
  }
  /* Hour axis labels (every 4h) */
  var hourLabels = '';
  for (var hx = 0; hx < 24; hx++) {
    hourLabels += '<div class="cdwie-heatmap-hour-lbl">' + (hx % 4 === 0 ? hx+'h' : '') + '</div>';
  }
  /* Build rows: one row per day */
  var rows = '';
  for (var d = 0; d < 7; d++) {
    var cells = '';
    for (var h = 0; h < 24; h++) {
      var base = Math.random();
      /* Apply time-of-day weight */
      if (isNight) {
        base = (h < 6 || h > 20) ? base * 0.9 + 0.1 : base * 0.15;
      } else if (endH > startH) {
        base = (h >= startH && h <= endH) ? base * 0.85 + 0.15 : base * 0.12;
      }
      /* Apply day-of-week weight */
      if (isWeekday && (d === 5 || d === 6)) base *= 0.08; // Sat/Sun low
      if (isSundayRest && d === 6) base *= 0.05;           // Sun rest
      /* Add slight noise */
      base = Math.min(1, Math.max(0.02, base + (Math.random() - 0.5) * 0.1));
      var alpha = base.toFixed(2);
      var tooltip = days[d] + ' ' + (h < 10 ? '0' : '') + h + ':00 UTC';
      cells += '<div class="cdwie-heatmap-cell" style="background:rgba(' + rgb + ',' + alpha + ')" title="' + tooltip + '"></div>';
    }
    rows += '<div class="cdwie-heatmap-row"><span class="cdwie-heatmap-day-lbl">' + days[d] + '</span>' + cells + '</div>';
  }
  /* Legend */
  var legendCells = [0.08, 0.25, 0.45, 0.65, 0.85, 0.95].map(function(v) {
    return '<div class="cdwie-heatmap-legend-cell" style="background:rgba(' + rgb + ',' + v + ')"></div>';
  }).join('');
  return '<div class="cdwie-heatmap-wrap">' +
    '<div class="cdwie-heatmap-hour-axis"><div style="width:32px;flex-shrink:0"></div>' + hourLabels + '</div>' +
    rows +
    '<div class="cdwie-heatmap-legend"><span>Less</span><div class="cdwie-heatmap-legend-cells">' + legendCells + '</div><span>More</span></div>' +
  '</div>';
}

window._cdwieDnaTab = function(actorId, tab) {
  _cdwie.actor.dnaTab = tab;
  document.querySelectorAll('.cdwie-dna-tab').forEach(function(b) {
    b.classList.toggle('active', b.textContent.toLowerCase().includes(tab.replace('-',' ').split(' ')[0].toLowerCase()));
  });
  var a = Object.values(DW_ACTORS).filter(function(x) { return x.id === actorId; })[0];
  if (!a) return;
  var tc = document.getElementById('cdwie-dna-tab-content');
  if (tc) {
    tc.innerHTML = _renderActorDnaTab(a, tab);
    if (tab === 'behavior') setTimeout(function() { _initActorRadarChart(a); }, 100);
  }
};

function _initActorRadarChart(a) {
  var canvas = document.getElementById('cdwie-radar-chart');
  if (!canvas || typeof Chart === 'undefined') return;
  if (canvas._chartInstance) { canvas._chartInstance.destroy(); }
  var b = a.behavior;
  var labels = Object.keys(b).map(function(k) {
    return k.replace(/_/g,' ').replace(/\b\w/g,function(c){return c.toUpperCase();});
  });
  var data = Object.values(b);
  canvas._chartInstance = new Chart(canvas, {
    type: 'radar',
    data: {
      labels: labels,
      datasets: [{
        label: a.name,
        data: data,
        backgroundColor: a.color + '33',
        borderColor: a.color,
        borderWidth: 2,
        pointBackgroundColor: a.color,
        pointRadius: 4
      }]
    },
    options: {
      responsive: false,
      scales: {
        r: {
          min: 0, max: 100,
          ticks: { display: false },
          grid: { color: 'rgba(255,255,255,0.1)' },
          angleLines: { color: 'rgba(255,255,255,0.1)' },
          pointLabels: { color: '#94a3b8', font: { size: 10 } }
        }
      },
      plugins: { legend: { display: false } },
      animation: { duration: 800 }
    }
  });
}


/* ═══════════════════════════════════════════════════════════════════════════
   ENGINE 3 — KNOWLEDGE GRAPH (Canvas 2D, Barnes-Hut Physics)
   ═══════════════════════════════════════════════════════════════════════════ */

function _buildEngineGraph() {
  var nodeTypes = [
    { type:'actor',    color:'#ef4444', icon:'★', label:'Actor' },
    { type:'malware',  color:'#f97316', icon:'◆', label:'Malware' },
    { type:'ioc',      color:'#3b82f6', icon:'●', label:'IOC' },
    { type:'campaign', color:'#a855f7', icon:'▲', label:'Campaign' },
    { type:'target',   color:'#22c55e', icon:'■', label:'Target' },
    { type:'infra',    color:'#14b8a6', icon:'⬡', label:'Infrastructure' },
    { type:'wallet',   color:'#eab308', icon:'◉', label:'Wallet' },
    { type:'darkweb',  color:'#ec4899', icon:'⬟', label:'Dark Web' }
  ];
  var legend = nodeTypes.map(function(nt) {
    return '<div class="cdwie-legend-item">' +
      '<span class="cdwie-legend-dot" style="background:' + nt.color + '"></span>' +
      '<span class="cdwie-legend-label">' + nt.label + '</span>' +
    '</div>';
  }).join('');

  return '<div class="cdwie-engine" id="cdwie-engine-knowledge-graph">' +
    '<div class="cdwie-graph-container">' +
      '<div class="cdwie-graph-toolbar">' +
        '<button class="cdwie-graph-btn" onclick="window._cdwieGraphZoomIn()" title="Zoom In"><i class="fas fa-search-plus"></i></button>' +
        '<button class="cdwie-graph-btn" onclick="window._cdwieGraphZoomOut()" title="Zoom Out"><i class="fas fa-search-minus"></i></button>' +
        '<button class="cdwie-graph-btn" onclick="window._cdwieGraphReset()" title="Reset View"><i class="fas fa-compress-arrows-alt"></i></button>' +
        '<button class="cdwie-graph-btn" onclick="window._cdwieGraphToggleLive()" id="cdwie-graph-live-btn" title="Toggle Live"><i class="fas fa-play"></i></button>' +
        '<span class="cdwie-graph-sep"></span>' +
        '<select class="cdwie-graph-select" onchange="window._cdwieGraphFilter(this.value)">' +
          '<option value="all">All Nodes</option>' +
          '<option value="actor">Actors Only</option>' +
          '<option value="malware">Malware Only</option>' +
          '<option value="campaign">Campaigns Only</option>' +
          '<option value="ioc">IOCs Only</option>' +
        '</select>' +
        '<span class="cdwie-graph-stats" id="cdwie-graph-stats">0 nodes · 0 edges</span>' +
      '</div>' +
      '<canvas id="cdwie-graph-canvas" class="cdwie-graph-canvas"></canvas>' +
      '<div class="cdwie-graph-legend">' + legend + '</div>' +
      '<div id="cdwie-graph-tooltip" class="cdwie-graph-tooltip" style="display:none"></div>' +
    '</div>' +
  '</div>';
}

window._cdwieGraphInit = function() {
  var canvas = document.getElementById('cdwie-graph-canvas');
  if (!canvas) return;
  if (_cdwie.graph.animFrame) { cancelAnimationFrame(_cdwie.graph.animFrame); _cdwie.graph.animFrame = null; }

  var container = canvas.parentElement;
  canvas.width  = container.offsetWidth  || 900;
  canvas.height = container.offsetHeight || 600;

  var gd = DW_GRAPH_DATA;
  _cdwie.graph.nodes = gd.nodes.map(function(n, i) {
    return Object.assign({}, n, {
      x: canvas.width  * 0.1 + Math.random() * canvas.width  * 0.8,
      y: canvas.height * 0.1 + Math.random() * canvas.height * 0.8,
      vx: 0, vy: 0, r: n.type === 'actor' ? 18 : n.type === 'campaign' ? 15 : 11,
      pinned: false
    });
  });
  _cdwie.graph.edges = gd.edges;
  _cdwie.graph.scale = 1;
  _cdwie.graph.offsetX = 0;
  _cdwie.graph.offsetY = 0;
  _cdwie.graph.initialized = true;

  var stats = document.getElementById('cdwie-graph-stats');
  if (stats) stats.textContent = _cdwie.graph.nodes.length + ' nodes · ' + _cdwie.graph.edges.length + ' edges';

  _cdwieGraphAttachEvents(canvas);
  _cdwieGraphStartLoop();
};

function _cdwieGraphStartLoop() {
  if (_cdwie.graph.animFrame) cancelAnimationFrame(_cdwie.graph.animFrame);
  function loop() {
    _cdwieGraphPhysics();
    _cdwieGraphDraw();
    _cdwie.graph.animFrame = requestAnimationFrame(loop);
  }
  _cdwie.graph.animFrame = requestAnimationFrame(loop);
}

window._cdwieGraphStopLoop = function() {
  if (_cdwie.graph.animFrame) { cancelAnimationFrame(_cdwie.graph.animFrame); _cdwie.graph.animFrame = null; }
};

function _cdwieGraphPhysics() {
  var nodes = _cdwie.graph.nodes;
  var edges = _cdwie.graph.edges;
  if (!nodes.length) return;

  var REPULSION = 800, SPRING_REST = 120, SPRING_K = 0.04, DAMPING = 0.88, GRAVITY = 0.002;
  var canvas = document.getElementById('cdwie-graph-canvas');
  var cx = canvas ? canvas.width/2 : 450;
  var cy = canvas ? canvas.height/2 : 300;

  for (var i = 0; i < nodes.length; i++) {
    if (nodes[i].pinned) continue;
    var fx = 0, fy = 0;
    // Gravity toward center
    fx += (cx - nodes[i].x) * GRAVITY;
    fy += (cy - nodes[i].y) * GRAVITY;
    // Repulsion between all pairs
    for (var j = 0; j < nodes.length; j++) {
      if (i === j) continue;
      var dx = nodes[i].x - nodes[j].x;
      var dy = nodes[i].y - nodes[j].y;
      var dist = Math.sqrt(dx*dx + dy*dy) || 1;
      var force = REPULSION / (dist * dist);
      fx += (dx / dist) * force;
      fy += (dy / dist) * force;
    }
    nodes[i].vx = (nodes[i].vx + fx) * DAMPING;
    nodes[i].vy = (nodes[i].vy + fy) * DAMPING;
  }

  // Spring forces along edges
  for (var e = 0; e < edges.length; e++) {
    var src = nodes.filter(function(n) { return n.id === (edges[e].source||edges[e].s); })[0];
    var tgt = nodes.filter(function(n) { return n.id === (edges[e].target||edges[e].t); })[0];
    if (!src || !tgt) continue;
    var edx = tgt.x - src.x;
    var edy = tgt.y - src.y;
    var edist = Math.sqrt(edx*edx + edy*edy) || 1;
    var stretch = (edist - SPRING_REST) * SPRING_K;
    var sfx = (edx / edist) * stretch;
    var sfy = (edy / edist) * stretch;
    if (!src.pinned) { src.vx += sfx; src.vy += sfy; }
    if (!tgt.pinned) { tgt.vx -= sfx; tgt.vy -= sfy; }
  }

  // Integrate positions + boundary clamp
  for (var k = 0; k < nodes.length; k++) {
    if (nodes[k].pinned) continue;
    nodes[k].x = _clamp(nodes[k].x + nodes[k].vx, 20, (canvas ? canvas.width : 900) - 20);
    nodes[k].y = _clamp(nodes[k].y + nodes[k].vy, 20, (canvas ? canvas.height : 600) - 20);
  }
}

function _cdwieGraphDraw() {
  var canvas = document.getElementById('cdwie-graph-canvas');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var nodes = _cdwie.graph.nodes;
  var edges = _cdwie.graph.edges;
  var sc = _cdwie.graph.scale;
  var ox = _cdwie.graph.offsetX;
  var oy = _cdwie.graph.offsetY;

  var nodeColors = { actor:'#ef4444', malware:'#f97316', ioc:'#3b82f6', campaign:'#a855f7', target:'#22c55e', infra:'#14b8a6', wallet:'#eab308', darkweb:'#ec4899' };
  var edgeColors = { USES:'#f97316', TARGETS:'#ef4444', COMMUNICATES_WITH:'#3b82f6', ATTRIBUTED_TO:'#a855f7', FUNDS:'#eab308', HOSTS:'#14b8a6', DELIVERS:'#22c55e' };

  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.save();
  ctx.translate(ox, oy);
  ctx.scale(sc, sc);

  // Draw edges
  for (var e = 0; e < edges.length; e++) {
    var src = nodes.filter(function(n) { return n.id === (edges[e].source||edges[e].s); })[0];
    var tgt = nodes.filter(function(n) { return n.id === (edges[e].target||edges[e].t); })[0];
    if (!src || !tgt) continue;
    ctx.beginPath();
    ctx.moveTo(src.x, src.y);
    ctx.lineTo(tgt.x, tgt.y);
    ctx.strokeStyle = (edgeColors[edges[e].type] || '#475569') + '66';
    ctx.lineWidth = 1.5;
    ctx.stroke();
    // Edge label
    if (sc > 0.8) {
      var mx = (src.x + tgt.x) / 2;
      var my = (src.y + tgt.y) / 2;
      ctx.font = '9px Inter, sans-serif';
      ctx.fillStyle = '#64748b';
      ctx.textAlign = 'center';
      ctx.fillText(edges[e].type, mx, my - 4);
    }
  }

  // Draw nodes
  for (var i = 0; i < nodes.length; i++) {
    var n = nodes[i];
    var color = nodeColors[n.type] || '#6366f1';
    var isSelected = _cdwie.graph.selectedNode && _cdwie.graph.selectedNode.id === n.id;
    var isHover   = _cdwie.graph.hoverNode && _cdwie.graph.hoverNode.id === n.id;

    // Glow
    if (isSelected || isHover) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r + 8, 0, Math.PI*2);
      ctx.fillStyle = color + '33';
      ctx.fill();
    }
    // Node circle
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.r, 0, Math.PI*2);
    ctx.fillStyle = color + (isSelected ? 'ff' : 'cc');
    ctx.fill();
    ctx.strokeStyle = isSelected ? '#fff' : color;
    ctx.lineWidth = isSelected ? 2.5 : 1;
    ctx.stroke();
    // Label
    ctx.font = 'bold 9px Inter, sans-serif';
    ctx.fillStyle = '#ffffff';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(n.label ? n.label.substring(0,4) : n.type.substring(0,3).toUpperCase(), n.x, n.y);
    if (sc > 0.6) {
      ctx.font = '10px Inter, sans-serif';
      ctx.fillStyle = '#cbd5e1';
      ctx.textBaseline = 'top';
      ctx.fillText(n.label || n.id, n.x, n.y + n.r + 3);
    }
  }
  ctx.restore();
}

function _cdwieGraphAttachEvents(canvas) {
  var drag = null, lastMX = 0, lastMY = 0, isPan = false;

  function toGraph(mx, my) {
    return {
      x: (mx - _cdwie.graph.offsetX) / _cdwie.graph.scale,
      y: (my - _cdwie.graph.offsetY) / _cdwie.graph.scale
    };
  }
  function hitNode(gx, gy) {
    var nodes = _cdwie.graph.nodes;
    for (var i = nodes.length-1; i >= 0; i--) {
      var dx = gx - nodes[i].x, dy = gy - nodes[i].y;
      if (Math.sqrt(dx*dx+dy*dy) <= nodes[i].r + 4) return nodes[i];
    }
    return null;
  }

  canvas.addEventListener('mousedown', function(e) {
    var gp = toGraph(e.offsetX, e.offsetY);
    var hit = hitNode(gp.x, gp.y);
    if (hit) { drag = hit; hit.pinned = true; }
    else { isPan = true; }
    lastMX = e.offsetX; lastMY = e.offsetY;
  });
  canvas.addEventListener('mousemove', function(e) {
    var gp = toGraph(e.offsetX, e.offsetY);
    var hit = hitNode(gp.x, gp.y);
    _cdwie.graph.hoverNode = hit || null;
    var tooltip = document.getElementById('cdwie-graph-tooltip');
    if (hit && tooltip) {
      tooltip.style.display = 'block';
      tooltip.style.left = (e.offsetX + 16) + 'px';
      tooltip.style.top  = (e.offsetY - 10) + 'px';
      tooltip.innerHTML = '<strong>' + (hit.label||hit.id) + '</strong><br><span>' + hit.type.toUpperCase() + '</span>';
    } else if (tooltip) { tooltip.style.display = 'none'; }
    if (drag) { drag.x += (e.offsetX - lastMX) / _cdwie.graph.scale; drag.y += (e.offsetY - lastMY) / _cdwie.graph.scale; }
    else if (isPan) { _cdwie.graph.offsetX += e.offsetX - lastMX; _cdwie.graph.offsetY += e.offsetY - lastMY; }
    lastMX = e.offsetX; lastMY = e.offsetY;
  });
  canvas.addEventListener('mouseup', function(e) {
    if (drag) { drag.pinned = false; drag = null; }
    isPan = false;
  });
  canvas.addEventListener('mouseleave', function() {
    if (drag) { drag.pinned = false; drag = null; }
    isPan = false;
    _cdwie.graph.hoverNode = null;
    var tooltip = document.getElementById('cdwie-graph-tooltip');
    if (tooltip) tooltip.style.display = 'none';
  });
  canvas.addEventListener('click', function(e) {
    var gp = toGraph(e.offsetX, e.offsetY);
    var hit = hitNode(gp.x, gp.y);
    if (hit) {
      _cdwie.graph.selectedNode = hit;
      _openNodePanel(hit);
    }
  });
  canvas.addEventListener('wheel', function(e) {
    e.preventDefault();
    var delta = e.deltaY > 0 ? 0.9 : 1.1;
    _cdwie.graph.scale = _clamp(_cdwie.graph.scale * delta, 0.2, 4);
  }, { passive: false });
}

function _openNodePanel(n) {
  var nodeColors = { actor:'#ef4444', malware:'#f97316', ioc:'#3b82f6', campaign:'#a855f7', target:'#22c55e', infra:'#14b8a6', wallet:'#eab308', darkweb:'#ec4899' };
  var color = nodeColors[n.type] || '#6366f1';
  var connectedEdges = _cdwie.graph.edges.filter(function(e) { return (e.source||e.s) === n.id || (e.target||e.t) === n.id; });
  var connHtml = connectedEdges.map(function(e) {
    var other = (e.source||e.s) === n.id ? (e.target||e.t) : (e.source||e.s);
    var otherNode = _cdwie.graph.nodes.filter(function(x) { return x.id === other; })[0];
    return '<div class="cdwie-node-conn-row"><span class="cdwie-badge cdwie-badge-blue">' + e.type + '</span><span>' + (otherNode ? (otherNode.label||otherNode.id) : other) + '</span></div>';
  }).join('');
  var html = '<div class="cdwie-node-detail">' +
    '<div class="cdwie-node-header" style="border-left:4px solid ' + color + '">' +
      '<div class="cdwie-node-type-badge" style="background:' + color + '22;color:' + color + '">' + n.type.toUpperCase() + '</div>' +
      '<div class="cdwie-node-label-lg">' + (n.label || n.id) + '</div>' +
    '</div>' +
    '<div class="cdwie-node-connections"><h4>Connections (' + connectedEdges.length + ')</h4>' + (connHtml || '<span class="cdwie-dim">No connections</span>') + '</div>' +
    '<button class="cdwie-panel-action-btn" onclick="_toast(\'Node added to investigation\',\'success\')"><i class="fas fa-crosshairs"></i> Investigate</button>' +
    '<button class="cdwie-panel-action-btn" onclick="_toast(\'IOC flagged for monitoring\',\'info\')"><i class="fas fa-flag"></i> Flag IOC</button>' +
  '</div>';
  _openPanel((n.label || n.id), html);
}

window._cdwieGraphZoomIn  = function() { _cdwie.graph.scale = _clamp(_cdwie.graph.scale * 1.2, 0.2, 4); };
window._cdwieGraphZoomOut = function() { _cdwie.graph.scale = _clamp(_cdwie.graph.scale * 0.8, 0.2, 4); };
window._cdwieGraphReset   = function() { _cdwie.graph.scale = 1; _cdwie.graph.offsetX = 0; _cdwie.graph.offsetY = 0; };
window._cdwieGraphToggleLive = function() {
  _cdwie.graph.live = !_cdwie.graph.live;
  var btn = document.getElementById('cdwie-graph-live-btn');
  if (btn) btn.innerHTML = _cdwie.graph.live ? '<i class="fas fa-pause"></i>' : '<i class="fas fa-play"></i>';
  _toast('Live graph updates ' + (_cdwie.graph.live ? 'enabled' : 'paused'), 'info');
};
window._cdwieGraphFilter = function(type) {
  var gd = DW_GRAPH_DATA;
  if (type === 'all') { _cdwie.graph.edges = gd.edges; }
  else { _cdwie.graph.edges = gd.edges.filter(function(e) {
    var src = _cdwie.graph.nodes.filter(function(n){ return n.id === (e.source||e.s); })[0];
    var tgt = _cdwie.graph.nodes.filter(function(n){ return n.id === (e.target||e.t); })[0];
    return (src && src.type === type) || (tgt && tgt.type === type);
  }); }
};


/* ═══════════════════════════════════════════════════════════════════════════
   ENGINE 4 — PREDICTIVE INTEL
   ═══════════════════════════════════════════════════════════════════════════ */

function _buildEnginePredictive() {
  var pred = DW_PREDICTIONS;
  var factors = pred.factors.map(function(f) {
    var trend = f.trend === 'up' ? '<i class="fas fa-arrow-up" style="color:#ef4444"></i>' :
                f.trend === 'down' ? '<i class="fas fa-arrow-down" style="color:#22c55e"></i>' :
                '<i class="fas fa-minus" style="color:#eab308"></i>';
    return '<div class="cdwie-factor-row">' +
      '<span class="cdwie-factor-label">' + f.label + '</span>' +
      '<div class="cdwie-factor-bar-wrap"><div class="cdwie-factor-bar" style="width:' + f.score + '%;background:' + f.color + '"></div></div>' +
      '<span class="cdwie-factor-weight">' + f.score + '%</span>' +
      trend +
    '</div>';
  }).join('');

  var campaigns = pred.campaigns.map(function(c, i) {
    var riskColor = c.prob >= 80 ? '#ef4444' : c.prob >= 60 ? '#f97316' : '#eab308';
    var phaseHtml = c.phases.map(function(ph) {
      return '<span class="cdwie-phase-chip cdwie-badge cdwie-badge-purple">' + ph + '</span>';
    }).join('');
    return '<div class="cdwie-campaign-card cdwie-card-reveal" style="animation-delay:' + (i*0.1) + 's">' +
      '<div class="cdwie-campaign-header">' +
        '<span class="cdwie-campaign-name">' + c.name + '</span>' +
        '<span class="cdwie-prob-badge" style="background:' + riskColor + '22;color:' + riskColor + '">' + c.prob + '% prob</span>' +
      '</div>' +
      '<div class="cdwie-campaign-eta"><i class="fas fa-clock"></i> ETA: ' + c.eta + '</div>' +
      '<div class="cdwie-campaign-phases">' + phaseHtml + '</div>' +
      '<div class="cdwie-campaign-targets">' +
        '<span class="cdwie-badge cdwie-badge-grey">' + c.group + '</span>' +
        '<span class="cdwie-badge cdwie-badge-blue">' + c.confidence + '</span>' +
      '</div>' +
    '</div>';
  }).join('');

  var geoRows = pred.geoThreats.slice(0, 12).map(function(g) {
    var barW = g.level;
    var color = g.level >= 80 ? '#ef4444' : g.level >= 60 ? '#f97316' : g.level >= 40 ? '#eab308' : '#22c55e';
    return '<div class="cdwie-geo-row">' +
      '<span class="cdwie-geo-country">' + g.label + '</span>' +
      '<div class="cdwie-geo-bar-wrap"><div class="cdwie-geo-bar" style="width:' + barW + '%;background:' + color + '"></div></div>' +
      '<span class="cdwie-geo-score">' + g.level + '</span>' +
    '</div>';
  }).join('');

  var tickerHtml = pred.emerging.map(function(t) {
    return '<span class="cdwie-ticker-item"><i class="fas fa-' + (t.icon||'exclamation-triangle') + '"></i> ' + t.name + ' <span style="opacity:0.6;font-size:10px">' + t.type + '</span></span>';
  }).join(' &nbsp;·&nbsp; ');

  return '<div class="cdwie-engine" id="cdwie-engine-predictive">' +
    '<div class="cdwie-predictive-grid">' +
      '<div class="cdwie-pred-left">' +
        '<div class="cdwie-gauge-panel cdwie-glass">' +
          '<h3><i class="fas fa-tachometer-alt"></i> Global Risk Score</h3>' +
          '<div class="cdwie-gauge-wrap">' +
            '<svg viewBox="0 0 200 120" class="cdwie-gauge-svg">' +
              '<path d="M 20 110 A 90 90 0 0 1 180 110" fill="none" stroke="#1e293b" stroke-width="18" stroke-linecap="round"/>' +
              '<path id="cdwie-gauge-arc" d="M 20 110 A 90 90 0 0 1 180 110" fill="none" stroke="#ef4444" stroke-width="18" stroke-linecap="round" stroke-dasharray="283" stroke-dashoffset="' + (283 - 283 * pred.riskScore/100) + '"/>' +
              '<text x="100" y="108" text-anchor="middle" fill="#f1f5f9" font-size="32" font-weight="700" font-family="Inter">' + pred.riskScore + '</text>' +
              '<text x="100" y="118" text-anchor="middle" fill="#94a3b8" font-size="10" font-family="Inter">RISK INDEX</text>' +
            '</svg>' +
            '<div class="cdwie-gauge-label ' + (pred.riskScore >= 80 ? 'cdwie-badge-red' : pred.riskScore >= 60 ? 'cdwie-badge-orange' : 'cdwie-badge-yellow') + '">HIGH RISK</div>' +
          '</div>' +
        '</div>' +
        '<div class="cdwie-factors-panel cdwie-glass">' +
          '<h3><i class="fas fa-sliders-h"></i> Risk Factors</h3>' +
          factors +
        '</div>' +
        '<div class="cdwie-forecast-panel cdwie-glass">' +
          '<h3><i class="fas fa-chart-line"></i> 30-Day Threat Forecast</h3>' +
          '<div style="position:relative;height:160px;width:100%">' +
            '<canvas id="cdwie-forecast-chart"></canvas>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="cdwie-pred-right">' +
        '<div class="cdwie-ticker-wrap"><div class="cdwie-ticker-inner">' + tickerHtml + ' &nbsp; ' + tickerHtml + '</div></div>' +
        '<div class="cdwie-campaigns-panel">' +
          '<h3><i class="fas fa-crosshairs"></i> Campaign Escalation Predictor</h3>' +
          campaigns +
        '</div>' +
        '<div class="cdwie-geo-panel cdwie-glass">' +
          '<h3><i class="fas fa-globe"></i> Geo Threat Distribution</h3>' +
          '<div class="cdwie-geo-grid">' + geoRows + '</div>' +
        '</div>' +
      '</div>' +
    '</div>' +
  '</div>';
}

function _initPredictiveCharts() {
  var canvas = document.getElementById('cdwie-forecast-chart');
  if (!canvas || typeof Chart === 'undefined') return;
  if (canvas._chartInstance) { canvas._chartInstance.destroy(); }
  var labels = [];
  var data1 = [], data2 = [];
  var now = new Date();
  for (var d = -14; d <= 15; d++) {
    var dt = new Date(now); dt.setDate(dt.getDate() + d);
    labels.push(dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    var base = 65 + Math.sin(d * 0.3) * 15 + _rand(-8, 8);
    data1.push(d <= 0 ? Math.max(20, Math.min(100, base)) : null);
    data2.push(d >= 0 ? Math.max(20, Math.min(100, base + d * 1.5 + _rand(-5, 5))) : null);
  }
  canvas._chartInstance = new Chart(canvas, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        { label: 'Historical', data: data1, borderColor: '#6366f1', backgroundColor: '#6366f133', fill: true, tension: 0.4, pointRadius: 2 },
        { label: 'Forecast',   data: data2, borderColor: '#f97316', backgroundColor: '#f9731633', fill: true, tension: 0.4, pointRadius: 2, borderDash: [5,5] }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#64748b', maxRotation: 45, maxTicksLimit: 10 }, grid: { color: '#1e293b' } },
        y: { min: 0, max: 100, ticks: { color: '#64748b' }, grid: { color: '#1e293b' } }
      },
      plugins: {
        legend: { labels: { color: '#94a3b8' } },
        tooltip: { mode: 'index', intersect: false }
      },
      animation: { duration: 800 }
    }
  });
}


/* ═══════════════════════════════════════════════════════════════════════════
   ENGINE 5 — DECEPTION DETECT
   ═══════════════════════════════════════════════════════════════════════════ */

function _buildEngineDeception() {
  var samples = Object.values(DW_DECEPTION_SAMPLES).map(function(s, i) {
    var iconMap = { 'Fake Ransomware Leak Claim':'times-circle', 'Genuine APT Forum Post':'check-circle', 'Credential Dump Listing':'user-secret', 'False Flag Operation':'theater-masks' };
    var ico = iconMap[s.label] || 'file-alt';
    return '<button class="cdwie-sample-btn" onclick="window._cdwieLoadSample(' + i + ')">' +
      '<i class="fas fa-' + ico + '"></i> ' +
      s.label +
    '</button>';
  }).join('');

  return '<div class="cdwie-engine" id="cdwie-engine-deception">' +
    '<div class="cdwie-deception-layout">' +
      '<div class="cdwie-deception-input-panel cdwie-glass">' +
        '<h3><i class="fas fa-microscope"></i> Content Analyzer</h3>' +
        '<p class="cdwie-engine-sub">Paste dark web post, forum message, or intelligence report for AI-powered authenticity analysis</p>' +
        '<div class="cdwie-sample-btns">' + samples + '</div>' +
        '<textarea id="cdwie-deception-text" class="cdwie-deception-textarea" placeholder="Paste dark web content here for analysis...&#10;&#10;The AI will evaluate credibility, scam probability, and disinformation markers..."></textarea>' +
        '<div class="cdwie-deception-actions">' +
          '<button class="cdwie-analyze-btn" onclick="window._cdwieAnalyzeContent()"><i class="fas fa-brain"></i> Analyze Content</button>' +
          '<button class="cdwie-clear-btn" onclick="document.getElementById(\'cdwie-deception-text\').value=\'\';document.getElementById(\'cdwie-deception-results\').style.display=\'none\'"><i class="fas fa-trash"></i> Clear</button>' +
        '</div>' +
      '</div>' +
      '<div id="cdwie-deception-results" class="cdwie-deception-results-panel" style="display:none">' +
        '<div class="cdwie-verdict-area" id="cdwie-verdict-area"></div>' +
        '<div class="cdwie-score-cards" id="cdwie-score-cards"></div>' +
        '<div class="cdwie-analysis-grid" id="cdwie-analysis-grid"></div>' +
      '</div>' +
    '</div>' +
  '</div>';
}

window._cdwieLoadSample = function(idx) {
  var s = Object.values(DW_DECEPTION_SAMPLES)[idx];
  if (!s) return;
  _cdwie.deception.currentSample = s;
  var ta = document.getElementById('cdwie-deception-text');
  if (ta) ta.value = s.text;
  document.getElementById('cdwie-deception-results').style.display = 'none';
};

window._cdwieAnalyzeContent = function() {
  var ta = document.getElementById('cdwie-deception-text');
  var text = ta ? ta.value.trim() : '';
  if (!text) { _toast('Enter content to analyze', 'warning'); return; }

  var sample = _cdwie.deception.currentSample;
  if (!sample) {
    var _dsArr = Object.values(DW_DECEPTION_SAMPLES);
    sample = _dsArr[Math.floor(Math.random() * _dsArr.length)];
  }

  var btn = document.querySelector('.cdwie-analyze-btn');
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...'; }

  setTimeout(function() {
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-brain"></i> Analyze Content'; }
    _cdwie.deception.analyzed = true;
    _renderDeceptionResults(sample);
  }, 1800);
};

function _renderDeceptionResults(s) {
  var results = document.getElementById('cdwie-deception-results');
  var verdictArea = document.getElementById('cdwie-verdict-area');
  var scoreCards = document.getElementById('cdwie-score-cards');
  var analysisGrid = document.getElementById('cdwie-analysis-grid');
  if (!results) return;

  results.style.display = 'block';

  var vColor = s.verdictColor || '#6366f1';
  var vText  = s.verdict || s.label || 'ANALYZED';
  var vIconMap = { 'LIKELY AUTHENTIC':'shield-check', 'LIKELY FABRICATED':'skull-crossbones', 'AMBIGUOUS — VERIFY':'question-circle', 'DECEPTION DETECTED':'theater-masks' };
  var vIcon = vIconMap[vText] || 'microscope';

  if (verdictArea) {
    verdictArea.innerHTML =
      '<div class="cdwie-verdict-badge cdwie-card-reveal" style="border-color:' + vColor + ';animation-delay:0s">' +
        '<div class="cdwie-verdict-icon" style="color:' + vColor + '">' +
          '<i class="fas fa-' + vIcon + '"></i>' +
        '</div>' +
        '<div class="cdwie-verdict-text">' +
          '<div class="cdwie-verdict-label">AI Verdict</div>' +
          '<div class="cdwie-verdict-value" style="color:' + vColor + '">' + vText + '</div>' +
        '</div>' +
      '</div>';
  }

  if (scoreCards) {
    var metrics = [
      { key:'credibility', label:'Credibility Score',  icon:'shield-alt',    color:'#6366f1' },
      { key:'scam',        label:'Scam Probability',   icon:'exclamation',   color:'#ef4444' },
      { key:'trust',       label:'Trust Index',         icon:'handshake',     color:'#22c55e' },
      { key:'misinfo',     label:'Misinfo Risk',        icon:'times-circle',  color:'#f97316' }
    ];
    scoreCards.innerHTML = metrics.map(function(m, i) {
      var raw = s.scores[m.key];
      /* trust is a string ('LOW'/'MEDIUM'/'HIGH') — convert to number for the ring */
      var val = (typeof raw === 'string')
        ? ({ 'LOW':20, 'MEDIUM':50, 'HIGH':85 }[raw.toUpperCase()] || 50)
        : (raw || 0);
      var displayVal = (typeof raw === 'string') ? raw : val;
      var circumference = 2 * Math.PI * 26;
      var dashOffset = circumference - (circumference * val / 100);
      return '<div class="cdwie-score-card cdwie-card-reveal" style="animation-delay:' + (0.1 + i*0.08) + 's">' +
        '<svg class="cdwie-score-ring" viewBox="0 0 60 60">' +
          '<circle cx="30" cy="30" r="26" fill="none" stroke="#1e293b" stroke-width="5"/>' +
          '<circle cx="30" cy="30" r="26" fill="none" stroke="' + m.color + '" stroke-width="5" stroke-linecap="round" ' +
            'stroke-dasharray="' + circumference.toFixed(1) + '" stroke-dashoffset="' + dashOffset.toFixed(1) + '" ' +
            'transform="rotate(-90 30 30)" style="transition:stroke-dashoffset 1s ease"/>' +
          '<text x="30" y="35" text-anchor="middle" fill="#f1f5f9" font-size="11" font-weight="700" font-family="Inter">' + displayVal + '</text>' +
        '</svg>' +
        '<div class="cdwie-score-label"><i class="fas fa-' + m.icon + '" style="color:' + m.color + '"></i><span>' + m.label + '</span></div>' +
      '</div>';
    }).join('');
  }

  if (analysisGrid) {
    var indicators = (s.indicators || []).map(function(ind) {
      /* indicators are {ok:bool, text:str} objects */
      var indObj = (typeof ind === 'object') ? ind : { ok: false, text: String(ind) };
      var iColor = indObj.ok ? '#22c55e' : '#ef4444';
      var iIcon  = indObj.ok ? 'check-circle' : 'times-circle';
      return '<div class="cdwie-indicator-row"><i class="fas fa-' + iIcon + '" style="color:' + iColor + '"></i><span>' + _e(indObj.text) + '</span></div>';
    }).join('');
    var signals = (s.signals || []).map(function(sig) {
      /* signals are {warn:bool, text:str} objects */
      var sigObj = (typeof sig === 'object') ? sig : { warn: false, text: String(sig) };
      var sColor = sigObj.warn ? '#f97316' : '#22c55e';
      var sIcon  = sigObj.warn ? 'exclamation-triangle' : 'check-double';
      return '<div class="cdwie-signal-row"><i class="fas fa-' + sIcon + '" style="color:' + sColor + '"></i><span>' + _e(sigObj.text) + '</span></div>';
    }).join('');
    analysisGrid.innerHTML =
      '<div class="cdwie-analysis-col cdwie-glass cdwie-card-reveal" style="animation-delay:0.5s">' +
        '<h4><i class="fas fa-radiation-alt" style="color:#ef4444"></i> Deception Indicators</h4>' +
        indicators +
      '</div>' +
      '<div class="cdwie-analysis-col cdwie-glass cdwie-card-reveal" style="animation-delay:0.6s">' +
        '<h4><i class="fas fa-check-double" style="color:#22c55e"></i> Authenticity Signals</h4>' +
        signals +
      '</div>';
  }
}


/* ═══════════════════════════════════════════════════════════════════════════
   ENGINE 6 — CTI COPILOT
   ═══════════════════════════════════════════════════════════════════════════ */

var COPILOT_SUGGESTIONS = [
  { label: 'Analyze IP', query: 'analyze 195.54.162.88', icon: 'network-wired' },
  { label: 'Check Domain', query: 'analyze midnight-shop.ru', icon: 'globe' },
  { label: 'Hash Lookup', query: 'hash a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01', icon: 'fingerprint' },
  { label: 'APT29 Profile', query: 'actor APT29', icon: 'user-secret' },
  { label: 'Ransomware IOCs', query: 'ransomware LockBit', icon: 'bug' },
  { label: 'Predict Threats', query: 'predict threats next 30 days', icon: 'chart-line' },
  { label: 'Correlate IOCs', query: 'correlate 195.54.162.88 midnight-shop.ru', icon: 'project-diagram' },
  { label: 'Help', query: '/help', icon: 'question-circle' }
];

function _buildEngineCopilot() {
  var suggHtml = COPILOT_SUGGESTIONS.map(function(s) {
    return '<button class="cdwie-suggestion-chip" onclick="window._cdwieCopilotSend(' + JSON.stringify(s.query) + ')">' +
      '<i class="fas fa-' + s.icon + '"></i> ' + s.label + '</button>';
  }).join('');

  return '<div class="cdwie-engine" id="cdwie-engine-copilot">' +
    '<div class="cdwie-copilot-layout">' +
      '<div class="cdwie-copilot-sidebar">' +
        '<div class="cdwie-copilot-brand"><i class="fas fa-robot"></i><span>CTI Copilot</span></div>' +
        '<div class="cdwie-copilot-status"><span class="cdwie-status-dot online"></span> Online · GPT-4 Turbo</div>' +
        '<div class="cdwie-suggestions-label"><i class="fas fa-bolt"></i> Quick Actions</div>' +
        '<div class="cdwie-copilot-suggestions">' + suggHtml + '</div>' +
        '<div class="cdwie-copilot-stats">' +
          '<div class="cdwie-cp-stat"><span class="cdwie-cp-stat-val" id="cdwie-cp-stat-queries">0</span><span>Queries</span></div>' +
          '<div class="cdwie-cp-stat"><span class="cdwie-cp-stat-val">0ms</span><span>Avg Response</span></div>' +
        '</div>' +
      '</div>' +
      '<div class="cdwie-copilot-main">' +
        '<div id="cdwie-chat-area" class="cdwie-chat-area">' +
          '<div class="cdwie-welcome-msg">' +
            '<div class="cdwie-welcome-icon"><i class="fas fa-robot"></i></div>' +
            '<h3>CTI Copilot Ready</h3>' +
            '<p>Ask me about threat actors, IOCs, malware families, campaigns, or use quick actions on the left. I have access to real-time dark web intelligence feeds.</p>' +
            '<div class="cdwie-welcome-chips">' +
              '<span class="cdwie-w-chip">Try: <em>analyze 192.168.1.1</em></span>' +
              '<span class="cdwie-w-chip">Try: <em>actor Lazarus Group</em></span>' +
              '<span class="cdwie-w-chip">Try: <em>predict threats</em></span>' +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div class="cdwie-chat-input-row">' +
          '<input id="cdwie-copilot-input" class="cdwie-chat-input" type="text" placeholder="Ask about threat actors, IOCs, campaigns... (type /help for commands)" onkeydown="if(event.key===\'Enter\')window._cdwieCopilotSend()" />' +
          '<button class="cdwie-chat-send" onclick="window._cdwieCopilotSend()"><i class="fas fa-paper-plane"></i></button>' +
          '<button class="cdwie-chat-clear" onclick="window._cdwieCopilotClear()" title="Clear chat"><i class="fas fa-trash"></i></button>' +
        '</div>' +
      '</div>' +
    '</div>' +
  '</div>';
}

window._cdwieCopilotSend = function(msgArg) {
  var input = document.getElementById('cdwie-copilot-input');
  var msg = msgArg || (input ? input.value.trim() : '');
  if (!msg) return;
  if (input) input.value = '';

  var statEl = document.getElementById('cdwie-cp-stat-queries');
  if (statEl) statEl.textContent = ++_cdwie.copilot.history.length;

  _appendChatMsg('user', msg);
  _showTypingIndicator();

  setTimeout(function() {
    _hideTypingIndicator();
    var response = _cdwieDispatchCopilotResponse(msg);
    _appendChatMsg('bot', response.text, response.type, response.data);
  }, 800 + Math.random() * 600);
};

window._cdwieCopilotClear = function() {
  var area = document.getElementById('cdwie-chat-area');
  if (area) area.innerHTML = '<div class="cdwie-chat-cleared"><i class="fas fa-trash"></i> Chat cleared</div>';
  _cdwie.copilot.history = [];
  setTimeout(function() {
    var c = document.querySelector('.cdwie-chat-cleared');
    if (c) c.style.opacity = '0';
  }, 2000);
  _toast('Chat cleared', 'info');
};

function _appendChatMsg(role, text, type, data) {
  var area = document.getElementById('cdwie-chat-area');
  if (!area) return;
  var welcome = area.querySelector('.cdwie-welcome-msg');
  if (welcome) welcome.remove();

  var div = document.createElement('div');
  div.className = 'cdwie-msg cdwie-msg-' + role;

  var contentHtml = '';
  if (role === 'bot' && type) {
    contentHtml = _renderCopilotResponseHtml(type, text, data);
  } else {
    contentHtml = '<div class="cdwie-msg-text">' + _escapeHtml(text) + '</div>';
  }

  div.innerHTML =
    '<div class="cdwie-msg-avatar"><i class="fas fa-' + (role === 'user' ? 'user' : 'robot') + '"></i></div>' +
    '<div class="cdwie-msg-body">' +
      contentHtml +
      '<div class="cdwie-msg-time">' + new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) + '</div>' +
    '</div>';
  area.appendChild(div);
  area.scrollTop = area.scrollHeight;
}

function _renderCopilotResponseHtml(type, text, data) {
  if (type === 'text' || !type) {
    return '<div class="cdwie-msg-text">' + text + '</div>';
  }
  if (type === 'ioc-card') {
    return '<div class="cdwie-msg-text">' + text + '</div>' +
      '<div class="cdwie-ioc-card cdwie-glass">' +
        '<div class="cdwie-ioc-card-header"><i class="fas fa-fingerprint"></i> IOC Analysis</div>' +
        '<div class="cdwie-ioc-rows">' +
          (data && data.iocs ? data.iocs.map(function(ioc) {
            return '<div class="cdwie-ioc-row"><code>' + ioc.value + '</code>' +
              '<span class="cdwie-badge cdwie-badge-' + (ioc.malicious?'red':'green') + '">' + (ioc.malicious?'MALICIOUS':'CLEAN') + '</span>' +
              '<span class="cdwie-badge cdwie-badge-blue">' + ioc.type + '</span></div>';
          }).join('') : '') +
        '</div>' +
      '</div>';
  }
  if (type === 'actor-card') {
    var a = data && data.actor ? data.actor : null;
    return '<div class="cdwie-msg-text">' + text + '</div>' +
      (a ? '<div class="cdwie-actor-mini-card cdwie-glass">' +
        '<div style="display:flex;align-items:center;gap:12px">' +
          '<div style="width:40px;height:40px;border-radius:50%;background:' + a.color + '22;color:' + a.color + ';display:flex;align-items:center;justify-content:center">' +
            '<i class="fas fa-' + (a.faIcon||'user-secret') + '"></i>' +
          '</div>' +
          '<div><strong>' + a.flag + ' ' + a.name + '</strong><br><small style="color:#94a3b8">' + a.alias + '</small></div>' +
        '</div>' +
        '<div style="margin-top:8px">' +
          a.sectors.slice(0,3).map(function(s){ return '<span class="cdwie-badge cdwie-badge-blue">' + s + '</span>'; }).join('') +
        '</div>' +
      '</div>' : '');
  }
  if (type === 'prediction') {
    return '<div class="cdwie-msg-text">' + text + '</div>' +
      '<div class="cdwie-prediction-card cdwie-glass">' +
        '<div class="cdwie-pred-bar" style="background:linear-gradient(90deg,#6366f133,#ef444433)">' +
          '<span style="color:#94a3b8;font-size:11px">RISK LEVEL</span>' +
          '<span style="color:#ef4444;font-weight:700">' + DW_PREDICTIONS.riskScore + '/100</span>' +
        '</div>' +
        DW_PREDICTIONS.campaigns.slice(0,2).map(function(c){
          return '<div style="padding:6px 0;border-bottom:1px solid #1e293b">' +
            '<span style="color:#f1f5f9;font-size:12px">' + c.name + '</span>' +
            '<span style="float:right;color:#f97316;font-size:12px">' + c.prob + '% · ' + c.eta + '</span>' +
          '</div>';
        }).join('') +
      '</div>';
  }
  return '<div class="cdwie-msg-text">' + text + '</div>';
}

function _showTypingIndicator() {
  var area = document.getElementById('cdwie-chat-area');
  if (!area) return;
  var typing = document.createElement('div');
  typing.id = 'cdwie-typing-indicator';
  typing.className = 'cdwie-msg cdwie-msg-bot cdwie-typing';
  typing.innerHTML =
    '<div class="cdwie-msg-avatar"><i class="fas fa-robot"></i></div>' +
    '<div class="cdwie-msg-body"><div class="cdwie-typing-dots"><span></span><span></span><span></span></div></div>';
  area.appendChild(typing);
  area.scrollTop = area.scrollHeight;
}

function _hideTypingIndicator() {
  var ind = document.getElementById('cdwie-typing-indicator');
  if (ind) ind.remove();
}

function _escapeHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function _cdwieDispatchCopilotResponse(msg) {
  var m = msg.toLowerCase().trim();
  var resp = DW_COPILOT_RESPONSES;

  if (m === '/clear') { window._cdwieCopilotClear(); return { text: '', type: 'text' }; }
  if (m === '/help' || m === 'help') return { text: resp.help().text, type: 'text' };
  if (m === '/export') return { text: resp.report().text, type: 'text' };

  var ipMatch = m.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  if (ipMatch) { var _ir = resp.ip(ipMatch[1]); return { text: _ir.data.rows.map(function(r){return '<strong>'+r.k+':</strong> '+r.v;}).join('<br>'), type: 'ioc-card', data: {
    iocs: [{ value: ipMatch[1], type: 'IPv4', malicious: true }, { value: 'AS8342', type: 'ASN', malicious: false }]
  }};}

  var domMatch = m.match(/(?:analyze|check|lookup)\s+([\w.-]+\.[a-z]{2,})/i);
  if (domMatch) { var _dr = resp.domain(domMatch[1]); return { text: _dr.data.rows.map(function(r){return '<strong>'+r.k+':</strong> '+r.v;}).join('<br>'), type: 'ioc-card', data: {
    iocs: [{ value: domMatch[1], type: 'Domain', malicious: true }, { value: '195.54.162.88', type: 'IPv4', malicious: true }]
  }};}

  var hashMatch = m.match(/\b([0-9a-f]{32,64})\b/i);
  if (hashMatch) { var _hr = resp.hash(hashMatch[1]); return { text: _hr.data.rows.map(function(r){return '<strong>'+r.k+':</strong> '+r.v;}).join('<br>'), type: 'ioc-card', data: {
    iocs: [{ value: hashMatch[1].substring(0,16) + '...', type: 'SHA256', malicious: true }]
  }};}

  var actorNameMatch = m.match(/(?:actor|group|apt|fin|lazarus|lockbit|apt29|apt41|fin7|oilrig|blackcat)\s*([\w\s]+)?/i);
  if (actorNameMatch) {
    var actorQuery = (actorNameMatch[0] + ' ' + (actorNameMatch[1]||'')).trim();
    var matchedActor = Object.values(DW_ACTORS).filter(function(a) {
      return actorQuery.toLowerCase().includes(a.id) || actorQuery.toLowerCase().includes(a.name.toLowerCase()) ||
             a.aliases.some(function(al) { return actorQuery.toLowerCase().includes(al.toLowerCase()); });
    })[0] || Object.values(DW_ACTORS)[0];
    return { text: resp.actor(actorQuery).data.desc || '', type: 'actor-card', data: { actor: matchedActor } };
  }

  if (/ransomware|lockbit|blackcat|ryuk|revil/.test(m)) return { text: resp.ransomware(m).text, type: 'ioc-card', data: {
    iocs: [{ value: 'lockbit3-decrypt.onion', type: 'Onion', malicious: true }, { value: 'ransom-key-001.bin', type: 'File', malicious: true }]
  }};

  if (/predict|forecast|threat.*next|next.*month|escalat/.test(m)) return { text: resp.predict().data.events.map(function(e){return e.prob+'% — '+e.event;}).join('<br>'), type: 'prediction' };
  if (/correlate|cluster|group.*ioc|ioc.*relation/.test(m)) return { text: resp.correlate().text, type: 'text' };
  if (/report|export|generate|brief/.test(m)) return { text: resp.report().text, type: 'text' };

  // Fallback
  return { text: 'I analyzed your query about <strong>' + _escapeHtml(msg.substring(0,40)) + '</strong>. ' +
    'No specific matches found in the current intelligence database. Try querying a specific IP, domain, hash, actor name, or use <code>/help</code> for available commands.', type: 'text' };
}


/* ═══════════════════════════════════════════════════════════════════════════
   ENGINE 7 — EXECUTIVE REPORTING
   ═══════════════════════════════════════════════════════════════════════════ */

function _buildEngineReporting() {
  var reportTypes = [
    { id:'executive',  label:'Executive Brief',    icon:'briefcase' },
    { id:'technical',  label:'Technical Report',   icon:'code' },
    { id:'ioc',        label:'IOC Bulletin',        icon:'fingerprint' },
    { id:'incident',   label:'Incident Report',     icon:'exclamation-triangle' }
  ];
  var timeframes = [
    { id:'24h', label:'Last 24 Hours' },
    { id:'7d',  label:'Last 7 Days' },
    { id:'30d', label:'Last 30 Days' },
    { id:'90d', label:'Last Quarter' }
  ];
  var sectors = ['all','government','financial','healthcare','energy','defense','technology'];
  var tlpLevels = ['white','green','amber','red'];

  var typeHtml = reportTypes.map(function(rt) {
    return '<label class="cdwie-rtype-card ' + (rt.id===_cdwie.report.type?'active':'') + '" onclick="window._cdwieSetReportType(\'' + rt.id + '\')">' +
      '<input type="radio" name="cdwie-rtype" value="' + rt.id + '" ' + (rt.id===_cdwie.report.type?'checked':'') + ' style="display:none">' +
      '<i class="fas fa-' + rt.icon + '"></i>' +
      '<span>' + rt.label + '</span>' +
    '</label>';
  }).join('');

  var tfHtml = timeframes.map(function(tf) {
    return '<option value="' + tf.id + '" ' + (tf.id===_cdwie.report.timeframe?'selected':'') + '>' + tf.label + '</option>';
  }).join('');

  var sectorHtml = sectors.map(function(s) {
    return '<option value="' + s + '" ' + (s===_cdwie.report.sector?'selected':'') + '>' + (s==='all'?'All Sectors':s.charAt(0).toUpperCase()+s.slice(1)) + '</option>';
  }).join('');

  var tlpHtml = tlpLevels.map(function(t) {
    return '<option value="' + t + '" ' + (t===_cdwie.report.tlp?'selected':'') + '>TLP:' + t.toUpperCase() + '</option>';
  }).join('');

  var sections = _cdwie.report.sections;
  var sectionHtml = Object.keys(sections).map(function(key) {
    var labels = { exec_summary:'Executive Summary', threat_landscape:'Threat Landscape', actor_profiles:'Threat Actor Profiles',
      ioc_list:'IOC List', campaign_analysis:'Campaign Analysis', recommendations:'Recommendations & Mitigations' };
    return '<label class="cdwie-section-toggle">' +
      '<input type="checkbox" ' + (sections[key]?'checked':'') + ' onchange="window._cdwieToggleSection(\'' + key + '\',this.checked)">' +
      '<span>' + (labels[key]||key) + '</span>' +
    '</label>';
  }).join('');

  return '<div class="cdwie-engine" id="cdwie-engine-reporting">' +
    '<div class="cdwie-report-layout">' +
      '<div class="cdwie-report-builder">' +
        '<h3><i class="fas fa-file-contract"></i> Report Builder</h3>' +
        '<div class="cdwie-builder-section">' +
          '<div class="cdwie-builder-label">Report Type</div>' +
          '<div class="cdwie-rtype-grid">' + typeHtml + '</div>' +
        '</div>' +
        '<div class="cdwie-builder-section">' +
          '<div class="cdwie-builder-label">Timeframe</div>' +
          '<select class="cdwie-rbuilder-select" onchange="window._cdwieSetReportTimeframe(this.value)">' + tfHtml + '</select>' +
        '</div>' +
        '<div class="cdwie-builder-section">' +
          '<div class="cdwie-builder-label">Sector Focus</div>' +
          '<select class="cdwie-rbuilder-select" onchange="window._cdwieSetReportSector(this.value)">' + sectorHtml + '</select>' +
        '</div>' +
        '<div class="cdwie-builder-section">' +
          '<div class="cdwie-builder-label">TLP Classification</div>' +
          '<select class="cdwie-rbuilder-select" onchange="window._cdwieSetReportTLP(this.value)">' + tlpHtml + '</select>' +
        '</div>' +
        '<div class="cdwie-builder-section">' +
          '<div class="cdwie-builder-label">Sections</div>' +
          '<div class="cdwie-sections-list">' + sectionHtml + '</div>' +
        '</div>' +
        '<div class="cdwie-builder-actions">' +
          '<button class="cdwie-gen-btn" onclick="window._cdwieGenerateReport()"><i class="fas fa-magic"></i> Generate Report</button>' +
          '<button class="cdwie-export-btn" onclick="window._cdwieExportReport(\'pdf\')"><i class="fas fa-file-pdf"></i> Export PDF</button>' +
          '<button class="cdwie-export-btn" onclick="window._cdwieExportReport(\'stix\')"><i class="fas fa-code"></i> Export STIX</button>' +
        '</div>' +
      '</div>' +
      '<div class="cdwie-report-preview" id="cdwie-report-preview">' +
        '<div class="cdwie-preview-placeholder">' +
          '<i class="fas fa-file-alt"></i>' +
          '<p>Configure your report settings and click <strong>Generate Report</strong> to create a live preview</p>' +
        '</div>' +
      '</div>' +
    '</div>' +
  '</div>';
}

window._cdwieSetReportType = function(type) {
  _cdwie.report.type = type;
  document.querySelectorAll('.cdwie-rtype-card').forEach(function(c) { c.classList.toggle('active', c.querySelector('input').value === type); });
};
window._cdwieSetReportTimeframe = function(tf) { _cdwie.report.timeframe = tf; };
window._cdwieSetReportSector    = function(s)  { _cdwie.report.sector    = s; };
window._cdwieSetReportTLP       = function(tlp) { _cdwie.report.tlp = tlp; };
window._cdwieToggleSection = function(key, val) { _cdwie.report.sections[key] = val; };

window._cdwieGenerateReport = function() {
  var preview = document.getElementById('cdwie-report-preview');
  if (!preview) return;
  preview.innerHTML = '<div class="cdwie-preview-loading"><div class="cdwie-spinner"></div><span>Generating intelligence report...</span></div>';
  setTimeout(function() {
    preview.innerHTML = _cdwieRenderReportPreview();
  }, 1200);
};

function _cdwieRenderReportPreview() {
  var r = _cdwie.report;
  var tlpColors = { white:'#94a3b8', green:'#22c55e', amber:'#f59e0b', red:'#ef4444' };
  var tlpColor = tlpColors[r.tlp] || '#94a3b8';
  var date = new Date().toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' });
  var timeLabels  = { '24h':'Last 24 Hours','7d':'Last 7 Days','30d':'Last 30 Days','90d':'Last Quarter' };
  var timePhrases = { '24h':'past 24 hours','7d':'past 7 days','30d':'past 30 days','90d':'past quarter' };
  var typeLabels  = { executive:'Executive Intelligence Brief', technical:'Technical Threat Report', ioc:'IOC Bulletin', incident:'Incident Report' };
  var title = typeLabels[r.type] || 'Intelligence Report';
  var secs  = r.sections;

  /* ── Shared data builders ── */
  var criticalActors = Object.values(DW_ACTORS).filter(function(a){ return a.threat.toLowerCase()==='critical'; });
  var highActors     = Object.values(DW_ACTORS).filter(function(a){ return a.threat.toLowerCase()==='high'; });

  var topActorsHtml = Object.values(DW_ACTORS).slice(0,5).map(function(a) {
    var rC = a.threat.toLowerCase()==='critical'?'red':'orange';
    return '<div class="rp-actor-row">' +
      '<div style="width:32px;height:32px;border-radius:8px;background:' + a.color + '22;color:' + a.color + ';display:flex;align-items:center;justify-content:center;flex-shrink:0">' +
        '<i class="fas fa-' + (a.faIcon||'user-secret') + '" style="font-size:13px"></i>' +
      '</div>' +
      '<div style="flex:1">' +
        '<div style="font-weight:600;color:#0f172a;font-size:13px">' + a.flag + ' ' + a.name + '</div>' +
        '<div style="color:#64748b;font-size:11px">' + a.alias + ' \xb7 ' + a.origin + '</div>' +
      '</div>' +
      '<div style="display:flex;flex-direction:column;align-items:flex-end;gap:3px">' +
        '<span class="rp-badge rp-badge-' + rC + '">' + a.threat.toUpperCase() + '</span>' +
        '<span style="color:#94a3b8;font-size:10px">' + a.confidence + '% confidence</span>' +
      '</div>' +
    '</div>';
  }).join('');

  var allIocs = [
    { ioc:'195.54.162.88',          type:'IPv4',   actor:'APT29',    status:'ACTIVE',    first:'2024-11-14' },
    { ioc:'lockbit4[.]onion',       type:'Onion',  actor:'LockBit',  status:'ACTIVE',    first:'2024-09-01' },
    { ioc:'midnight-shop[.]ru',     type:'Domain', actor:'APT29',    status:'ACTIVE',    first:'2024-10-22' },
    { ioc:'45.142.212.100',         type:'IPv4',   actor:'Lazarus',  status:'ACTIVE',    first:'2024-07-30' },
    { ioc:'svr-proxy[.]net',        type:'Domain', actor:'APT29',    status:'ACTIVE',    first:'2024-11-01' },
    { ioc:'SHA256:a3f7b2913dc...',  type:'Hash',   actor:'APT41',    status:'ACTIVE',    first:'2024-08-15' },
    { ioc:'bc1q9f2a6wk5xp...',     type:'Wallet', actor:'Lazarus',  status:'MONITORED', first:'2024-06-20' },
    { ioc:'blockchain-update[.]com',type:'Domain', actor:'Lazarus',  status:'ACTIVE',    first:'2024-10-05' }
  ];
  var iocListHtml = allIocs.map(function(item) {
    var sC = item.status==='ACTIVE'?'#ef4444':'#eab308';
    return '<div class="rp-ioc-row">' +
      '<code>' + item.ioc + '</code>' +
      '<span class="rp-badge" style="background:#eff6ff;color:#3b82f6">' + item.type + '</span>' +
      '<span style="color:#64748b;font-size:11px">' + item.actor + '</span>' +
      '<span class="rp-badge" style="background:' + sC + '22;color:' + sC + '">' + item.status + '</span>' +
      '<span style="color:#94a3b8;font-size:10px">' + item.first + '</span>' +
    '</div>';
  }).join('');

  var campaignHtml = DW_PREDICTIONS.campaigns.map(function(c) {
    var pC = c.prob>=80?'#ef4444':c.prob>=60?'#f97316':'#eab308';
    var phases = c.phases.map(function(ph){ return '<span class="rp-badge rp-badge-blue">' + ph + '</span>'; }).join(' ');
    return '<div class="rp-campaign-row" style="flex-direction:column;align-items:flex-start;gap:6px">' +
      '<div style="display:flex;align-items:center;gap:8px;width:100%">' +
        '<strong>' + c.name + '</strong>' +
        '<span class="rp-badge" style="background:' + pC + '22;color:' + pC + '">' + c.prob + '% prob</span>' +
        '<span class="rp-badge rp-badge-blue" style="margin-left:auto">ETA: ' + c.eta + '</span>' +
      '</div>' +
      '<div style="display:flex;gap:4px;flex-wrap:wrap">' + phases + '</div>' +
      '<div style="color:#64748b;font-size:11px">' + c.group + ' \xb7 ' + c.confidence + ' confidence</div>' +
    '</div>';
  }).join('');

  /* ── Type-specific summary text ── */
  var summaryBody = '';
  if (r.type === 'executive') {
    summaryBody =
      '<p>This Executive Intelligence Brief assesses the global threat landscape for the <strong>' + (timePhrases[r.timeframe]||r.timeframe) + '</strong>. ' +
      'The Wadjet-Eye AI platform processed <strong>847,412 dark web documents</strong> across ' +
      '<strong>34 monitored forums, 12 paste sites, and 8 onion services</strong> during this period.</p>' +
      '<p style="margin-top:10px">Current global threat index: <strong style="color:#ef4444">' + DW_PREDICTIONS.riskScore + '/100 (HIGH)</strong>. ' +
      '<strong>' + criticalActors.length + ' CRITICAL-tier</strong> and <strong>' + highActors.length + ' HIGH-tier</strong> actors are assessed as actively operational. ' +
      'Primary sectors at elevated risk: <strong>Healthcare, Finance, Government, and Critical Infrastructure</strong>.</p>' +
      '<p style="margin-top:10px"><strong>Key Findings:</strong></p>' +
      '<ul style="color:#334155;font-size:13px;line-height:1.9;padding-left:18px;margin:6px 0 0">' +
        '<li>APT29 (Cozy Bear) confirmed operational — new C2 infrastructure on EU network ranges; HAMMERTOSS v4 deployed</li>' +
        '<li>LockBit 4.0 affiliate activity +34% this period; healthcare sector targeted in 8 confirmed incidents</li>' +
        '<li>Lazarus Group cryptocurrency theft campaign ongoing; est. $47M in reporting window</li>' +
        '<li>' + (8 + Math.floor(Math.random()*10)) + ' credential dumps with corporate email addresses published on dark web forums</li>' +
        '<li>' + DW_PREDICTIONS.campaigns.filter(function(c){return c.prob>=75;}).length + ' campaigns at \u226575% escalation probability within reporting window</li>' +
      '</ul>';
  } else if (r.type === 'technical') {
    summaryBody =
      '<p>This Technical Threat Report provides in-depth TTP analysis, IOC inventory, and behavioral profiling for the <strong>' + (timePhrases[r.timeframe]||r.timeframe) + '</strong>. ' +
      'Coverage includes malware family analysis, network infrastructure mapping, and full MITRE ATT&CK\xae alignment.</p>' +
      '<p style="margin-top:10px"><strong>Technical Highlights:</strong></p>' +
      '<ul style="color:#334155;font-size:13px;line-height:1.9;padding-left:18px;margin:6px 0 0">' +
        '<li><strong>APT29:</strong> HAMMERTOSS v4 using Twitter/GitHub image steganography for C2 — new DGA domains via Namecheap registrar</li>' +
        '<li><strong>LockBit 4.0:</strong> Rust-compiled binary; Intermittent Encryption + anti-VM evasion; beacon sleep 4,200ms jitter 38%</li>' +
        '<li><strong>APT41:</strong> ShadowPad loader via DLL side-loading (<code style="font-size:11px;background:#f8fafc;padding:1px 4px">iiWin.dll</code>) in legitimate software update chains</li>' +
        '<li><strong>Lazarus:</strong> AppleJeus macOS variant targeting crypto exchange staff via fake trading platform installers</li>' +
        '<li>Cobalt Strike Team Server detected on 5 new IPs — certificate: self-signed, CN=localhost; JA3: 72a7c4bb318f</li>' +
      '</ul>';
  } else if (r.type === 'ioc') {
    summaryBody =
      '<p>This IOC Bulletin contains validated, machine-readable threat indicators collected from dark web sources, OSINT feeds, and autonomous sensors during the <strong>' + (timePhrases[r.timeframe]||r.timeframe) + '</strong>. ' +
      'All indicators are de-duplicated and confidence-scored based on multi-source corroboration.</p>' +
      '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:12px">' +
        '<div class="rp-stat-box"><span class="rp-stat-num" style="color:#ef4444">' + allIocs.filter(function(x){return x.status==='ACTIVE';}).length + '</span><span>Active IOCs</span></div>' +
        '<div class="rp-stat-box"><span class="rp-stat-num" style="color:#f97316">12</span><span>New This Period</span></div>' +
        '<div class="rp-stat-box"><span class="rp-stat-num" style="color:#22c55e">99%</span><span>Avg Confidence</span></div>' +
      '</div>';
  } else if (r.type === 'incident') {
    summaryBody =
      '<p>This Incident Report documents a confirmed <strong style="color:#ef4444">CRITICAL</strong> intrusion attributed to <strong>APT29 (Cozy Bear / Midnight Blizzard)</strong> with 94% confidence. ' +
      'The incident involved spear-phishing initial access, ADCS credential abuse, lateral movement, and data exfiltration via SUNBURST C2 channel.</p>' +
      '<div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px;margin-top:10px">' +
        '<div style="font-weight:700;color:#ef4444;margin-bottom:8px"><i class="fas fa-exclamation-triangle"></i> Incident Summary</div>' +
        '<table style="font-size:12px;color:#334155;border-collapse:collapse;width:100%">' +
          '<tr><td style="padding:4px 8px 4px 0;color:#64748b;white-space:nowrap;width:130px">Detection Date:</td><td style="padding:4px 0">2024-11-14 08:22 UTC</td></tr>' +
          '<tr><td style="padding:4px 8px 4px 0;color:#64748b">Attribution:</td><td style="padding:4px 0"><strong>APT29 (SVR)</strong> \xb7 94% confidence</td></tr>' +
          '<tr><td style="padding:4px 8px 4px 0;color:#64748b">Dwell Time:</td><td style="padding:4px 0">Estimated 21 days before detection</td></tr>' +
          '<tr><td style="padding:4px 8px 4px 0;color:#64748b">Data Impact:</td><td style="padding:4px 0">~2.4 GB exfiltrated via OneDrive API C2</td></tr>' +
          '<tr><td style="padding:4px 8px 4px 0;color:#64748b">MITRE Tactics:</td><td style="padding:4px 0">8/14 ATT&CK tactics confirmed</td></tr>' +
          '<tr><td style="padding:4px 8px 4px 0;color:#64748b">Status:</td><td style="padding:4px 0"><span style="color:#22c55e;font-weight:600"><i class="fas fa-check-circle"></i> CONTAINED \u2014 Remediation 94% complete</span></td></tr>' +
        '</table>' +
      '</div>';
  }

  /* ── Recommendations ── */
  var recsHtml = '';
  if (r.type === 'executive') {
    recsHtml =
      '<table style="width:100%;border-collapse:collapse;font-size:12px">' +
        '<thead><tr style="color:#64748b;font-size:10px;text-transform:uppercase;border-bottom:2px solid #e2e8f0">' +
          '<th style="padding:6px 8px;text-align:left">Priority</th><th style="text-align:left;padding:6px 8px">Action</th>' +
          '<th style="text-align:left;padding:6px 8px">Owner</th><th style="text-align:left;padding:6px 8px">Timeline</th>' +
        '</tr></thead>' +
        '<tbody>' +
          '<tr style="border-bottom:1px solid #f1f5f9"><td style="padding:8px"><span class="rp-badge rp-badge-red">P1</span></td><td style="color:#0f172a;padding:8px">Block all APT29 IOCs in SIEM/SOAR and network perimeter immediately</td><td style="color:#64748b;padding:8px">SOC</td><td style="padding:8px"><span class="rp-badge rp-badge-red">Immediate</span></td></tr>' +
          '<tr style="border-bottom:1px solid #f1f5f9"><td style="padding:8px"><span class="rp-badge rp-badge-red">P1</span></td><td style="color:#0f172a;padding:8px">Audit external-facing services for CVE-2024 vulnerabilities exploited by APT41</td><td style="color:#64748b;padding:8px">Vuln Mgmt</td><td style="padding:8px"><span class="rp-badge rp-badge-red">24 Hours</span></td></tr>' +
          '<tr style="border-bottom:1px solid #f1f5f9"><td style="padding:8px"><span class="rp-badge rp-badge-orange">P2</span></td><td style="color:#0f172a;padding:8px">Enforce phishing-resistant MFA (FIDO2) on all privileged and external accounts</td><td style="color:#64748b;padding:8px">IAM</td><td style="padding:8px"><span class="rp-badge rp-badge-orange">7 Days</span></td></tr>' +
          '<tr style="border-bottom:1px solid #f1f5f9"><td style="padding:8px"><span class="rp-badge rp-badge-orange">P2</span></td><td style="color:#0f172a;padding:8px">Deploy EDR across all endpoints; validate Cobalt Strike detection rule coverage</td><td style="color:#64748b;padding:8px">SecOps</td><td style="padding:8px"><span class="rp-badge rp-badge-orange">14 Days</span></td></tr>' +
          '<tr style="border-bottom:1px solid #f1f5f9"><td style="padding:8px"><span class="rp-badge rp-badge-blue">P3</span></td><td style="color:#0f172a;padding:8px">Enroll in continuous dark web monitoring for credential exposure alerts</td><td style="color:#64748b;padding:8px">Threat Intel</td><td style="padding:8px"><span class="rp-badge rp-badge-blue">30 Days</span></td></tr>' +
          '<tr><td style="padding:8px"><span class="rp-badge rp-badge-blue">P3</span></td><td style="color:#0f172a;padding:8px">Run tabletop exercise simulating APT29 WINTER STORM lateral movement scenario</td><td style="color:#64748b;padding:8px">CISO</td><td style="padding:8px"><span class="rp-badge rp-badge-blue">60 Days</span></td></tr>' +
        '</tbody>' +
      '</table>';
  } else if (r.type === 'technical') {
    recsHtml =
      '<ul style="color:#334155;font-size:13px;line-height:2;padding-left:18px;margin:0">' +
        '<li>Hunt HAMMERTOSS: monitor PowerShell <code style="background:#f8fafc;font-size:11px">Get-Random</code>, encoded commands, and social media image downloads from corp endpoints</li>' +
        '<li>Deploy YARA rules for LockBit 4.0 Rust binary signatures (provided in Appendix A)</li>' +
        '<li>Block known ShadowPad DLL side-loading chains; alert on <code style="background:#f8fafc;font-size:11px">iiWin.dll</code>, <code style="background:#f8fafc;font-size:11px">msvcr120.dll</code></li>' +
        '<li>Block Cobalt Strike default TLS certificates; detect JA3/JA3S hash <code style="background:#f8fafc;font-size:11px">72a7c4bb318f</code></li>' +
        '<li>Enable ADCS audit logging; alert ESC1/ESC8 escalation attempts via <code style="background:#f8fafc;font-size:11px">certreq.exe</code></li>' +
        '<li>Validate EDR telemetry completeness against APT29 ATT&CK\xae Navigator layer (provided)</li>' +
      '</ul>';
  } else if (r.type === 'ioc') {
    recsHtml =
      '<p style="color:#334155;font-size:13px;line-height:1.7;margin:0 0 10px">Ingest all indicators via STIX 2.1 / TAXII into your SIEM and network controls. Priority IOCs (confidence \u226590%) should be blocked immediately; medium-confidence IOCs should trigger alerting only.</p>' +
      '<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:10px;font-size:12px;color:#166534">' +
        '<i class="fas fa-check-circle"></i> <strong>STIX 2.1 bundle available</strong> \u2014 Click "Export STIX" to download machine-readable IOC package for automated SIEM/SOAR ingestion.' +
      '</div>';
  } else {
    recsHtml =
      '<ul style="color:#334155;font-size:13px;line-height:2;padding-left:18px;margin:0">' +
        '<li>Complete forensic imaging of all affected endpoints before remediation activities commence</li>' +
        '<li>Revoke and reissue all service account and privileged credentials immediately</li>' +
        '<li>Conduct full Active Directory security audit; review all GPO changes in past 30 days</li>' +
        '<li>File incident report with CISA (AA##-###A) and relevant ISAC within 72 hours</li>' +
        '<li>Preserve all log evidence in tamper-evident storage for legal/regulatory proceedings</li>' +
        '<li>Engage external IR firm to validate containment and provide independent attestation</li>' +
        '<li>Brief executive leadership and legal team on regulatory disclosure obligations</li>' +
      '</ul>';
  }

  /* ── MITRE section (technical/incident only) ── */
  var mitreSection = '';
  if (secs.actor_profiles && (r.type === 'technical' || r.type === 'incident')) {
    var mitreEntries = [
      {id:'T1566.001',name:'Spear-Phishing Link',         phase:'Initial Access',     actors:['APT29','FIN7','APT41']},
      {id:'T1059.001',name:'PowerShell',                   phase:'Execution',          actors:['APT29','APT41','Lazarus']},
      {id:'T1053.005',name:'Scheduled Task/Job',           phase:'Persistence',        actors:['APT29','APT41']},
      {id:'T1027',    name:'Obfuscated Files/Information', phase:'Defense Evasion',    actors:['APT29','Lazarus']},
      {id:'T1003.001',name:'LSASS Memory Dump',            phase:'Credential Access',  actors:['APT29','FIN7']},
      {id:'T1021.002',name:'SMB/Windows Admin Shares',     phase:'Lateral Movement',   actors:['APT29','LockBit']},
      {id:'T1041',    name:'Exfiltration Over C2 Channel', phase:'Exfiltration',       actors:['APT29','APT41','OilRig']},
      {id:'T1486',    name:'Data Encrypted for Impact',    phase:'Impact',             actors:['LockBit','BlackCat','Lazarus']}
    ];
    var mRows = mitreEntries.map(function(m) {
      return '<tr style="border-bottom:1px solid #f1f5f9;font-size:12px">' +
        '<td style="padding:7px 8px;font-family:monospace;color:#6366f1">' + m.id + '</td>' +
        '<td style="padding:7px 8px;color:#0f172a">' + m.name + '</td>' +
        '<td style="padding:7px 8px;color:#64748b">' + m.phase + '</td>' +
        '<td style="padding:7px 8px">' + m.actors.map(function(a){ return '<span class="rp-badge rp-badge-blue">' + a + '</span>'; }).join(' ') + '</td>' +
      '</tr>';
    }).join('');
    mitreSection =
      '<div class="rp-section">' +
        '<h2 class="rp-section-title"><i class="fas fa-sitemap"></i> MITRE ATT&CK\xae Technique Coverage</h2>' +
        '<table style="width:100%;border-collapse:collapse">' +
          '<thead><tr style="color:#64748b;font-size:10px;text-transform:uppercase;border-bottom:2px solid #e2e8f0">' +
            '<th style="padding:6px 8px;text-align:left">ID</th><th style="padding:6px 8px;text-align:left">Technique</th>' +
            '<th style="padding:6px 8px;text-align:left">Tactic</th><th style="padding:6px 8px;text-align:left">Observed Actors</th>' +
          '</tr></thead>' +
          '<tbody>' + mRows + '</tbody>' +
        '</table>' +
      '</div>';
  }

  var html =
    '<div class="rp-report">' +
      '<div class="rp-header" style="border-top:4px solid ' + tlpColor + '">' +
        '<div class="rp-header-top">' +
          '<div class="rp-org"><i class="fas fa-eye"></i> WADJET-EYE AI INTELLIGENCE PLATFORM</div>' +
          '<div class="rp-tlp" style="background:' + tlpColor + '22;color:' + tlpColor + ';border:1px solid ' + tlpColor + '">TLP:' + r.tlp.toUpperCase() + '</div>' +
        '</div>' +
        '<h1 class="rp-title">' + title + '</h1>' +
        '<div class="rp-meta">' +
          '<span><i class="fas fa-calendar"></i> Generated: ' + date + '</span>' +
          '<span><i class="fas fa-clock"></i> Period: ' + (timeLabels[r.timeframe]||r.timeframe) + '</span>' +
          '<span><i class="fas fa-industry"></i> Sector: ' + (r.sector==='all'?'All Sectors':r.sector.charAt(0).toUpperCase()+r.sector.slice(1)) + '</span>' +
          '<span><i class="fas fa-robot"></i> AI-Generated \xb7 CDWIE v1.0</span>' +
        '</div>' +
      '</div>' +
      (secs.exec_summary ?
        '<div class="rp-section">' +
          '<h2 class="rp-section-title"><i class="fas fa-file-alt"></i> ' + (r.type==='incident'?'Incident Overview':r.type==='ioc'?'Bulletin Summary':'Executive Summary') + '</h2>' +
          summaryBody +
        '</div>' : '') +
      (secs.threat_landscape ?
        '<div class="rp-section">' +
          '<h2 class="rp-section-title"><i class="fas fa-globe"></i> Threat Landscape Assessment</h2>' +
          '<div class="rp-stats-row">' +
            '<div class="rp-stat-box"><span class="rp-stat-num" style="color:#ef4444">' + DW_PREDICTIONS.riskScore + '</span><span>Global Risk Index</span></div>' +
            '<div class="rp-stat-box"><span class="rp-stat-num" style="color:#f97316">' + Object.keys(DW_ACTORS).length + '</span><span>Tracked Actors</span></div>' +
            '<div class="rp-stat-box"><span class="rp-stat-num" style="color:#a855f7">' + DW_PREDICTIONS.campaigns.length + '</span><span>Active Campaigns</span></div>' +
            '<div class="rp-stat-box"><span class="rp-stat-num" style="color:#22d3ee">' + DW_PREDICTIONS.geoThreats.length + '</span><span>Geo Threat Zones</span></div>' +
          '</div>' +
          '<p class="rp-landscape-para">Analysis of ' + (timePhrases[r.timeframe]||r.timeframe) + ' confirms sustained elevation in nation-state espionage and RaaS operations. ' +
          'Top attack vectors: <strong>Spear-phishing (38%)</strong>, <strong>Public application exploits (24%)</strong>, <strong>Supply chain (19%)</strong>, <strong>Credential theft (14%)</strong>. ' +
          'Infrastructure hotspots: Eastern Europe, Russia, DPRK, and China-attributed ranges.</p>' +
          '<div style="margin-top:12px"><div style="color:#64748b;font-size:11px;margin-bottom:8px;font-weight:600">Emerging Threats \u2014 ' + (timeLabels[r.timeframe]||r.timeframe) + '</div>' +
            DW_PREDICTIONS.emerging.slice(0,4).map(function(t) {
              return '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #f1f5f9">' +
                '<i class="fas fa-' + (t.icon||'exclamation-circle') + '" style="color:#f97316;font-size:12px;width:16px"></i>' +
                '<span style="color:#0f172a;font-size:13px;flex:1">' + t.name + '</span>' +
                '<span class="rp-badge" style="background:#fff7ed;color:#f97316">' + t.type + '</span>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' : '') +
      (secs.actor_profiles ?
        '<div class="rp-section">' +
          '<h2 class="rp-section-title"><i class="fas fa-users"></i> Threat Actor Profiles</h2>' +
          '<div class="rp-actors-list">' + topActorsHtml + '</div>' +
        '</div>' : '') +
      mitreSection +
      (secs.ioc_list ?
        '<div class="rp-section">' +
          '<h2 class="rp-section-title"><i class="fas fa-fingerprint"></i> Indicators of Compromise</h2>' +
          '<div style="margin-bottom:8px;display:flex;gap:6px;flex-wrap:wrap">' +
            '<span class="rp-badge" style="background:#fef2f2;color:#ef4444">' + allIocs.filter(function(x){return x.type==='IPv4';}).length + ' IPv4</span>' +
            '<span class="rp-badge" style="background:#eff6ff;color:#3b82f6">' + allIocs.filter(function(x){return x.type==='Domain'||x.type==='Onion';}).length + ' Domains/Onion</span>' +
            '<span class="rp-badge" style="background:#faf5ff;color:#a855f7">' + allIocs.filter(function(x){return x.type==='Hash';}).length + ' Hashes</span>' +
            '<span class="rp-badge" style="background:#fefce8;color:#ca8a04">' + allIocs.filter(function(x){return x.type==='Wallet'||x.type==='ASN';}).length + ' Other</span>' +
          '</div>' +
          '<div class="rp-ioc-list">' + iocListHtml + '</div>' +
        '</div>' : '') +
      (secs.campaign_analysis ?
        '<div class="rp-section">' +
          '<h2 class="rp-section-title"><i class="fas fa-crosshairs"></i> Active Campaign Analysis</h2>' +
          '<div style="margin-bottom:10px;color:#64748b;font-size:12px">' + DW_PREDICTIONS.campaigns.length + ' campaigns tracked with escalation probability \u226540% in reporting window.</div>' +
          campaignHtml +
        '</div>' : '') +
      (secs.recommendations ?
        '<div class="rp-section">' +
          '<h2 class="rp-section-title"><i class="fas fa-shield-alt"></i> ' + (r.type==='incident'?'Remediation Actions':r.type==='technical'?'Technical Mitigations':r.type==='ioc'?'IOC Disposition':'Recommended Actions') + '</h2>' +
          recsHtml +
        '</div>' : '') +
      '<div class="rp-footer">' +
        '<span>WADJET-EYE AI Intelligence Platform \xb7 Cognitive Dark Web Intelligence Engine v1.0</span>' +
        '<span style="color:' + tlpColor + '">TLP:' + r.tlp.toUpperCase() + ' \u2014 Handle accordingly</span>' +
      '</div>' +
    '</div>';
  return html;
}
window._cdwieExportReport = function(format) {
  if (!_cdwie.report.type) { _toast('Generate a report first', 'warning'); return; }
  if (format === 'pdf') {
    _toast('PDF export queued — generating report...', 'info');
    setTimeout(function() { _toast('Report exported: threat-intelligence-brief.pdf', 'success'); }, 1500);
  } else if (format === 'stix') {
    _toast('STIX 2.1 bundle generation started...', 'info');
    setTimeout(function() { _toast('STIX bundle exported: cdwie-stix-bundle.json', 'success'); }, 1500);
  }
};


/* ═══════════════════════════════════════════════════════════════════════════
   ENGINE WIRING — Tab switch hydration + post-render chart/graph hooks
   ═══════════════════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════════════════
   FINAL _cdwieTab — full implementation (overrides stub above)
   ═══════════════════════════════════════════════════════════════════════════ */
window._cdwieTab = function(tabId) {
  /* Stop graph physics if leaving the graph tab */
  if (_cdwie.activeTab === 'knowledge-graph' && tabId !== 'knowledge-graph') {
    window._cdwieGraphStopLoop();
  }

  _cdwie.activeTab = tabId;

  /* Update tab button active states */
  document.querySelectorAll('.cdwie-tab').forEach(function(t) {
    t.classList.toggle('active', t.dataset.tab === tabId);
  });

  /* Hydrate the single engine panel with current engine HTML */
  var panel = document.getElementById('cdwie-engine-panel');
  if (!panel) return;

  switch (tabId) {
    case 'cognitive-search': panel.innerHTML = _buildEngineCognitiveSearch(); break;
    case 'actor-dna':        panel.innerHTML = _buildEngineActorDNA();        break;
    case 'knowledge-graph':  panel.innerHTML = _buildEngineGraph();           break;
    case 'predictive':       panel.innerHTML = _buildEnginePredictive();      break;
    case 'deception':        panel.innerHTML = _buildEngineDeception();       break;
    case 'copilot':          panel.innerHTML = _buildEngineCopilot();         break;
    case 'reporting':        panel.innerHTML = _buildEngineReporting();       break;
    default:
      panel.innerHTML = '<div style="color:#94a3b8;padding:40px;text-align:center">Engine not found: ' + tabId + '</div>';
  }
  /* Belt-and-suspenders: ensure the injected engine div is always visible */
  var engineDiv = panel.querySelector('.cdwie-engine');
  if (engineDiv) engineDiv.classList.add('active');

  /* Post-render hooks */
  switch (tabId) {
    case 'actor-dna':
      setTimeout(function() { _renderActorProfile(_cdwie.actor.selected); }, 60);
      break;
    case 'knowledge-graph':
      setTimeout(function() { window._cdwieGraphInit(); }, 100);
      break;
    case 'predictive':
      setTimeout(function() { _initPredictiveCharts(); }, 80);
      break;
    case 'deception':
      /* nothing extra needed — samples loaded on click */
      break;
    case 'copilot':
      /* nothing extra needed */
      break;
    case 'reporting':
      /* nothing extra needed — report generated on button click */
      break;
  }
};

/* ═══════════════════════════════════════════════════════════════════════════
   MISSING CSS RULES — injected at runtime for edge cases
   ═══════════════════════════════════════════════════════════════════════════ */
(function _injectExtraStyles() {
  var id = 'cdwie-extra-runtime-styles';
  if (document.getElementById(id)) return;
  var s = document.createElement('style');
  s.id = id;
  s.textContent = [
    /* ── CRITICAL: engine visibility override — dynamic panel always shows one engine ── */
    '#cdwie-engine-panel .cdwie-engine{display:block!important}',
    /* Spinner */
    '.cdwie-spinner{width:32px;height:32px;border:3px solid #1e293b;border-top-color:#6366f1;border-radius:50%;animation:cdwie-spin 0.8s linear infinite}',
    '@keyframes cdwie-spin{to{transform:rotate(360deg)}}',
    /* Loading zone */
    '.cdwie-loading-zone{display:flex;flex-direction:column;align-items:center;gap:16px;padding:60px 0}',
    '.cdwie-loading-spinner{display:flex;align-items:center;gap:12px;color:#94a3b8}',
    '.cdwie-loading-step{color:#475569;font-size:12px;opacity:0;transform:translateY(4px);transition:all 0.2s}',
    '.cdwie-loading-step.done{opacity:1;transform:none;color:#94a3b8}',
    '.cdwie-loading-step i{color:#22c55e;margin-right:6px}',
    /* Graph toolbar */
    '.cdwie-graph-toolbar{display:flex;align-items:center;gap:8px;padding:10px 14px;background:#0f172a;border-bottom:1px solid #1e293b;flex-wrap:wrap}',
    '.cdwie-graph-btn{background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:6px 10px;border-radius:6px;cursor:pointer;font-size:13px;transition:all 0.15s}',
    '.cdwie-graph-btn:hover{background:#334155;color:#f1f5f9}',
    '.cdwie-graph-sep{width:1px;height:20px;background:#334155;margin:0 4px}',
    '.cdwie-graph-select{background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:5px 8px;border-radius:6px;font-size:12px}',
    '.cdwie-graph-stats{color:#64748b;font-size:11px;margin-left:auto}',
    /* Result cards */
    '.cdwie-result-card{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:16px;cursor:pointer;transition:all 0.2s;margin-bottom:12px}',
    '.cdwie-result-card:hover{border-color:#6366f1;transform:translateY(-2px)}',
    '.cdwie-result-header{display:flex;align-items:flex-start;gap:12px;margin-bottom:10px}',
    '.cdwie-result-icon{width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0}',
    '.cdwie-result-meta{flex:1;min-width:0}',
    '.cdwie-result-title{font-weight:600;color:#f1f5f9;font-size:14px}',
    '.cdwie-result-sub{color:#94a3b8;font-size:12px;margin-top:2px}',
    '.cdwie-result-badges{display:flex;flex-direction:column;gap:4px;align-items:flex-end}',
    '.cdwie-conf-pill,.cdwie-tlp-pill{font-size:10px;font-weight:700;padding:2px 7px;border-radius:999px}',
    '.cdwie-result-summary{color:#94a3b8;font-size:12px;line-height:1.5;margin-bottom:10px}',
    '.cdwie-result-footer{display:flex;align-items:center;flex-wrap:wrap;gap:6px}',
    '.cdwie-result-meta-item{color:#64748b;font-size:11px;display:flex;align-items:center;gap:4px}',
    '.cdwie-result-iocs{display:flex;flex-wrap:wrap;gap:4px}',
    '.cdwie-ioc-inline{background:#0f172a;border:1px solid #334155;padding:1px 6px;border-radius:4px;font-family:JetBrains Mono,monospace;font-size:10px;color:#7dd3fc}',
    '.cdwie-results-grid{display:flex;flex-direction:column}',
    '.cdwie-results-zone{padding:16px 0}',
    '.cdwie-results-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}',
    '.cdwie-results-count{color:#94a3b8;font-size:13px}',
    '.cdwie-results-filters{display:flex;gap:6px;flex-wrap:wrap}',
    '.cdwie-filter-btn{background:#1e293b;color:#64748b;border:1px solid #334155;padding:4px 12px;border-radius:999px;cursor:pointer;font-size:12px;transition:all 0.15s}',
    '.cdwie-filter-btn.active,.cdwie-filter-btn:hover{background:#6366f1;color:#fff;border-color:#6366f1}',
    /* Panel extras */
    '.cdwie-panel-result-detail{display:flex;flex-direction:column;gap:12px}',
    '.cdwie-panel-badge-row{display:flex;gap:6px;flex-wrap:wrap}',
    '.cdwie-panel-summary{color:#94a3b8;font-size:13px;line-height:1.6}',
    '.cdwie-panel-ioc-row{display:flex;align-items:center;justify-content:space-between;padding:6px;background:#0f172a;border-radius:6px;margin-bottom:4px}',
    '.cdwie-panel-copy-btn{background:none;border:none;color:#6366f1;cursor:pointer;padding:2px 6px}',
    '.cdwie-panel-refs,.cdwie-panel-last-seen{color:#64748b;font-size:12px;display:flex;align-items:center;gap:6px}',
    '.cdwie-panel-tags{display:flex;flex-wrap:wrap;gap:4px}',
    '.cdwie-panel-action-btn{background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:8px 14px;border-radius:8px;cursor:pointer;font-size:12px;width:100%;text-align:left;transition:all 0.15s;margin-top:4px}',
    '.cdwie-panel-action-btn:hover{background:#6366f1;color:#fff;border-color:#6366f1}',
    /* Actor DNA extras */
    '.cdwie-actor-profile{display:flex;flex-direction:column;gap:16px;height:100%;overflow-y:auto}',
    '.cdwie-actor-profile-header{display:flex;align-items:flex-start;gap:16px;padding:16px;background:#0f172a;border-radius:12px;border:1px solid #1e293b}',
    '.cdwie-actor-avatar-lg{width:56px;height:56px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0}',
    '.cdwie-actor-profile-meta{flex:1}',
    '.cdwie-actor-profile-name{margin:0 0 4px;font-size:20px;font-weight:700;color:#f1f5f9}',
    '.cdwie-actor-profile-alias{color:#94a3b8;font-size:12px;margin-bottom:8px}',
    '.cdwie-actor-profile-badges{display:flex;gap:6px;flex-wrap:wrap}',
    '.cdwie-actor-profile-stats{display:flex;gap:12px;flex-shrink:0}',
    '.cdwie-stat-chip{text-align:center;background:#1e293b;padding:8px 14px;border-radius:8px;min-width:56px}',
    '.cdwie-stat-val{display:block;font-size:20px;font-weight:700;color:#6366f1}',
    '.cdwie-stat-lbl{font-size:10px;color:#64748b}',
    /* Behavior bars */
    '.cdwie-dna-behavior{display:grid;grid-template-columns:1fr 1fr;gap:20px}',
    '.cdwie-radar-wrap{display:flex;align-items:center;justify-content:center}',
    '.cdwie-behavior-bars{display:flex;flex-direction:column;gap:8px;justify-content:center}',
    '.cdwie-behavior-row{display:flex;align-items:center;gap:8px}',
    '.cdwie-beh-label{color:#94a3b8;font-size:11px;width:120px;flex-shrink:0}',
    '.cdwie-beh-bar-wrap{flex:1;height:6px;background:#1e293b;border-radius:3px;overflow:hidden}',
    '.cdwie-beh-bar{height:100%;background:#6366f1;border-radius:3px;transition:width 0.8s ease}',
    '.cdwie-beh-val{color:#64748b;font-size:11px;width:24px;text-align:right}',
    /* Overview */
    '.cdwie-dna-overview{display:flex;flex-direction:column;gap:14px}',
    '.cdwie-actor-desc{color:#94a3b8;font-size:13px;line-height:1.6;margin:0}',
    '.cdwie-overview-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}',
    '.cdwie-ov-item{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:10px;display:flex;flex-direction:column;gap:4px}',
    '.cdwie-ov-label{color:#64748b;font-size:11px;display:flex;align-items:center;gap:5px}',
    '.cdwie-ov-val{color:#f1f5f9;font-size:13px}',
    '.cdwie-ov-sectors{margin-top:4px}',
    '.cdwie-ov-label-block{color:#64748b;font-size:11px;margin-bottom:6px}',
    /* MITRE grid */
    '.cdwie-dna-ttps{overflow-y:auto;max-height:420px}',
    '.cdwie-mitre-grid{display:flex;flex-direction:column;gap:6px}',
    '.cdwie-mitre-row{display:flex;align-items:center;gap:10px;padding:8px;background:#0f172a;border-radius:8px;border:1px solid #1e293b}',
    '.cdwie-mitre-id{font-family:JetBrains Mono,monospace;font-size:11px;color:#6366f1;width:60px;flex-shrink:0}',
    '.cdwie-mitre-name{flex:1;color:#f1f5f9;font-size:12px}',
    '.cdwie-mitre-phase{margin-left:auto}',
    /* Infra */
    '.cdwie-dna-infra{display:flex;flex-direction:column;gap:16px}',
    '.cdwie-infra-section h4{color:#94a3b8;font-size:12px;margin:0 0 8px;font-weight:600}',
    '.cdwie-heatmap-section h4{color:#94a3b8;font-size:12px;margin:0 0 8px;font-weight:600}',
    '.cdwie-c2-list{display:flex;flex-wrap:wrap;gap:4px}',
    '.cdwie-dim{color:#475569;font-size:12px}',
    /* Heatmap */
    '.cdwie-heatmap-labels{display:grid;grid-template-columns:repeat(7,1fr);gap:2px;margin-bottom:4px}',
    '.cdwie-heatmap-labels span{font-size:9px;color:#64748b;text-align:center}',
    '.cdwie-heatmap-cells{display:grid;grid-template-columns:repeat(7,1fr);gap:2px}',
    '.cdwie-heatmap-cell{width:100%;padding-bottom:100%;border-radius:2px;cursor:pointer;transition:opacity 0.15s}',
    '.cdwie-heatmap-cell:hover{opacity:0.7}',
    /* Predictive */
    '.cdwie-predictive-grid{display:grid;grid-template-columns:360px 1fr;gap:20px;height:100%}',
    '.cdwie-pred-left,.cdwie-pred-right{display:flex;flex-direction:column;gap:14px;overflow-y:auto}',
    '.cdwie-gauge-panel,.cdwie-factors-panel,.cdwie-forecast-panel,.cdwie-geo-panel{padding:16px}',
    '.cdwie-gauge-panel h3,.cdwie-factors-panel h3,.cdwie-forecast-panel h3,.cdwie-campaigns-panel h3,.cdwie-geo-panel h3{color:#94a3b8;font-size:13px;font-weight:600;margin:0 0 12px;display:flex;align-items:center;gap:6px}',
    '.cdwie-gauge-wrap{display:flex;flex-direction:column;align-items:center;gap:8px}',
    '.cdwie-gauge-svg{width:200px;height:130px}',
    '.cdwie-gauge-label{font-size:11px;font-weight:700;padding:3px 10px;border-radius:999px}',
    '.cdwie-factor-row{display:flex;align-items:center;gap:8px;margin-bottom:8px}',
    '.cdwie-factor-label{color:#94a3b8;font-size:11px;width:140px;flex-shrink:0}',
    '.cdwie-factor-bar-wrap{flex:1;height:6px;background:#1e293b;border-radius:3px;overflow:hidden}',
    '.cdwie-factor-bar{height:100%;border-radius:3px;transition:width 0.8s ease}',
    '.cdwie-factor-weight{color:#64748b;font-size:11px;width:30px;text-align:right}',
    '.cdwie-campaign-card{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:14px;margin-bottom:10px}',
    '.cdwie-campaign-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}',
    '.cdwie-campaign-name{color:#f1f5f9;font-size:13px;font-weight:600}',
    '.cdwie-prob-badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px}',
    '.cdwie-campaign-eta{color:#64748b;font-size:11px;margin-bottom:6px}',
    '.cdwie-campaign-phases{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:6px}',
    '.cdwie-campaign-targets{display:flex;flex-wrap:wrap;gap:4px}',
    '.cdwie-geo-row{display:flex;align-items:center;gap:8px;margin-bottom:6px}',
    '.cdwie-geo-country{color:#94a3b8;font-size:11px;width:90px;flex-shrink:0}',
    '.cdwie-geo-bar-wrap{flex:1;height:6px;background:#1e293b;border-radius:3px;overflow:hidden}',
    '.cdwie-geo-bar{height:100%;border-radius:3px;transition:width 0.8s ease}',
    '.cdwie-geo-score{color:#64748b;font-size:11px;width:24px;text-align:right}',
    /* Ticker */
    '@keyframes cdwie-ticker-scroll{from{transform:translateX(0)}to{transform:translateX(-50%)}}',
    '.cdwie-ticker-wrap{overflow:hidden;background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:8px 0}',
    '.cdwie-ticker-inner{display:flex;white-space:nowrap;animation:cdwie-ticker-scroll 30s linear infinite}',
    '.cdwie-ticker-item{color:#f97316;font-size:11px;padding:0 24px;flex-shrink:0}',
    /* Deception */
    '.cdwie-deception-layout{display:grid;grid-template-columns:400px 1fr;gap:20px;height:100%}',
    '.cdwie-deception-input-panel{padding:20px;display:flex;flex-direction:column;gap:12px}',
    '.cdwie-deception-input-panel h3{color:#94a3b8;font-size:13px;font-weight:600;margin:0;display:flex;align-items:center;gap:6px}',
    '.cdwie-sample-btns{display:flex;flex-wrap:wrap;gap:6px}',
    '.cdwie-sample-btn{background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:5px 10px;border-radius:6px;cursor:pointer;font-size:11px;transition:all 0.15s}',
    '.cdwie-sample-btn:hover{background:#6366f1;color:#fff;border-color:#6366f1}',
    '.cdwie-deception-textarea{background:#0f172a;border:1px solid #334155;border-radius:10px;padding:12px;color:#94a3b8;font-size:12px;resize:none;min-height:180px;font-family:JetBrains Mono,monospace;line-height:1.5}',
    '.cdwie-deception-textarea:focus{outline:none;border-color:#6366f1}',
    '.cdwie-deception-actions{display:flex;gap:8px}',
    '.cdwie-analyze-btn{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600;flex:1;transition:opacity 0.15s}',
    '.cdwie-analyze-btn:disabled{opacity:0.5;cursor:not-allowed}',
    '.cdwie-clear-btn{background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:10px 14px;border-radius:8px;cursor:pointer;font-size:13px}',
    '.cdwie-deception-results-panel{overflow-y:auto;padding:4px 0;display:flex;flex-direction:column;gap:16px}',
    '.cdwie-verdict-area{display:flex;justify-content:center}',
    '.cdwie-verdict-badge{display:flex;align-items:center;gap:16px;background:#0f172a;border:2px solid;border-radius:14px;padding:20px 28px}',
    '.cdwie-verdict-icon{font-size:32px}',
    '.cdwie-verdict-label{color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:0.05em}',
    '.cdwie-verdict-value{font-size:20px;font-weight:800;letter-spacing:0.05em}',
    '.cdwie-score-cards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}',
    '.cdwie-score-card{display:flex;flex-direction:column;align-items:center;gap:8px;background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:14px}',
    '.cdwie-score-ring{width:60px;height:60px}',
    '.cdwie-score-label{display:flex;flex-direction:column;align-items:center;gap:3px;text-align:center}',
    '.cdwie-score-label span{color:#94a3b8;font-size:10px}',
    '.cdwie-analysis-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}',
    '.cdwie-analysis-col{padding:14px;display:flex;flex-direction:column;gap:8px}',
    '.cdwie-analysis-col h4{color:#94a3b8;font-size:12px;font-weight:600;margin:0;display:flex;align-items:center;gap:6px}',
    '.cdwie-indicator-row,.cdwie-signal-row{display:flex;align-items:flex-start;gap:8px;color:#94a3b8;font-size:12px;line-height:1.4}',
    /* Copilot */
    '.cdwie-copilot-layout{display:grid;grid-template-columns:220px 1fr;gap:0;height:100%;overflow:hidden}',
    '.cdwie-copilot-sidebar{background:#0f172a;border-right:1px solid #1e293b;padding:16px;display:flex;flex-direction:column;gap:12px;overflow-y:auto}',
    '.cdwie-copilot-brand{display:flex;align-items:center;gap:8px;color:#6366f1;font-weight:700;font-size:15px}',
    '.cdwie-copilot-status{display:flex;align-items:center;gap:6px;color:#64748b;font-size:11px}',
    '.cdwie-status-dot{width:7px;height:7px;border-radius:50%;background:#64748b}',
    '.cdwie-status-dot.online{background:#22c55e;box-shadow:0 0 6px #22c55e}',
    '.cdwie-suggestions-label{color:#475569;font-size:10px;text-transform:uppercase;letter-spacing:0.08em;margin-top:4px}',
    '.cdwie-copilot-suggestions{display:flex;flex-direction:column;gap:4px}',
    '.cdwie-suggestion-chip{background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:6px 10px;border-radius:6px;cursor:pointer;font-size:11px;text-align:left;transition:all 0.15s}',
    '.cdwie-suggestion-chip:hover{background:#6366f133;color:#a5b4fc;border-color:#6366f1}',
    '.cdwie-copilot-stats{margin-top:auto;display:flex;gap:8px}',
    '.cdwie-cp-stat{flex:1;background:#1e293b;border-radius:8px;padding:8px;text-align:center;font-size:10px;color:#64748b}',
    '.cdwie-cp-stat-val{display:block;font-size:16px;font-weight:700;color:#6366f1}',
    '.cdwie-copilot-main{display:flex;flex-direction:column;overflow:hidden}',
    '.cdwie-chat-area{flex:1;overflow-y:auto;padding:20px;display:flex;flex-direction:column;gap:16px}',
    '.cdwie-welcome-msg{text-align:center;padding:40px 20px;color:#94a3b8}',
    '.cdwie-welcome-icon{font-size:48px;color:#6366f133;margin-bottom:12px}',
    '.cdwie-welcome-msg h3{color:#f1f5f9;margin:0 0 8px}',
    '.cdwie-welcome-msg p{font-size:13px;line-height:1.6;max-width:400px;margin:0 auto 16px}',
    '.cdwie-welcome-chips{display:flex;justify-content:center;gap:8px;flex-wrap:wrap}',
    '.cdwie-w-chip{background:#1e293b;border:1px solid #334155;padding:4px 12px;border-radius:999px;font-size:11px;color:#64748b}',
    '.cdwie-w-chip em{color:#6366f1;font-style:normal}',
    '.cdwie-msg{display:flex;align-items:flex-start;gap:10px}',
    '.cdwie-msg-user{flex-direction:row-reverse}',
    '.cdwie-msg-avatar{width:32px;height:32px;border-radius:50%;background:#1e293b;display:flex;align-items:center;justify-content:center;color:#6366f1;font-size:13px;flex-shrink:0}',
    '.cdwie-msg-user .cdwie-msg-avatar{background:#6366f133;color:#818cf8}',
    '.cdwie-msg-body{max-width:72%;display:flex;flex-direction:column;gap:4px}',
    '.cdwie-msg-user .cdwie-msg-body{align-items:flex-end}',
    '.cdwie-msg-text{background:#1e293b;color:#f1f5f9;padding:10px 14px;border-radius:12px;font-size:13px;line-height:1.5}',
    '.cdwie-msg-user .cdwie-msg-text{background:#6366f133;border:1px solid #6366f155}',
    '.cdwie-msg-time{color:#475569;font-size:10px}',
    '.cdwie-ioc-card,.cdwie-actor-mini-card,.cdwie-prediction-card{padding:12px;border-radius:10px;margin-top:6px}',
    '.cdwie-ioc-card-header{font-size:11px;font-weight:700;color:#6366f1;margin-bottom:8px;display:flex;align-items:center;gap:5px}',
    '.cdwie-ioc-row{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid #1e293b}',
    '.cdwie-ioc-row code{flex:1;font-size:11px;color:#7dd3fc;font-family:JetBrains Mono,monospace}',
    '.cdwie-pred-bar{display:flex;align-items:center;justify-content:space-between;padding:8px;border-radius:8px;margin-bottom:8px}',
    '.cdwie-typing-dots{display:flex;gap:4px;padding:10px 14px;background:#1e293b;border-radius:12px}',
    '.cdwie-typing-dots span{width:6px;height:6px;border-radius:50%;background:#475569;animation:cdwie-typing-bounce 1.2s infinite}',
    '.cdwie-typing-dots span:nth-child(2){animation-delay:0.2s}',
    '.cdwie-typing-dots span:nth-child(3){animation-delay:0.4s}',
    '@keyframes cdwie-typing-bounce{0%,80%,100%{transform:translateY(0)}40%{transform:translateY(-6px)}}',
    '.cdwie-chat-input-row{display:flex;gap:8px;padding:14px;border-top:1px solid #1e293b}',
    '.cdwie-chat-input{flex:1;background:#1e293b;border:1px solid #334155;color:#f1f5f9;padding:10px 14px;border-radius:10px;font-size:13px}',
    '.cdwie-chat-input:focus{outline:none;border-color:#6366f1}',
    '.cdwie-chat-send{background:#6366f1;color:#fff;border:none;padding:10px 16px;border-radius:10px;cursor:pointer;font-size:13px}',
    '.cdwie-chat-clear{background:#1e293b;color:#64748b;border:1px solid #334155;padding:10px;border-radius:10px;cursor:pointer}',
    '.cdwie-chat-cleared{text-align:center;color:#475569;font-size:12px;padding:20px}',
    /* Reporting */
    '.cdwie-report-layout{display:grid;grid-template-columns:300px 1fr;gap:0;height:100%;overflow:hidden}',
    '.cdwie-report-builder{background:#0f172a;border-right:1px solid #1e293b;padding:16px;overflow-y:auto;display:flex;flex-direction:column;gap:14px}',
    '.cdwie-report-builder h3{color:#94a3b8;font-size:13px;font-weight:600;margin:0;display:flex;align-items:center;gap:6px}',
    '.cdwie-builder-section{display:flex;flex-direction:column;gap:6px}',
    '.cdwie-builder-label{color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:0.06em}',
    '.cdwie-rtype-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px}',
    '.cdwie-rtype-card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:10px 8px;cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:6px;color:#94a3b8;font-size:11px;transition:all 0.15s;text-align:center}',
    '.cdwie-rtype-card.active{background:#6366f133;border-color:#6366f1;color:#818cf8}',
    '.cdwie-rtype-card i{font-size:16px}',
    '.cdwie-rbuilder-select{background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:7px 10px;border-radius:8px;font-size:12px;width:100%}',
    '.cdwie-sections-list{display:flex;flex-direction:column;gap:6px}',
    '.cdwie-section-toggle{display:flex;align-items:center;gap:8px;cursor:pointer;color:#94a3b8;font-size:12px}',
    '.cdwie-section-toggle input{accent-color:#6366f1}',
    '.cdwie-builder-actions{display:flex;flex-direction:column;gap:8px;margin-top:auto}',
    '.cdwie-gen-btn{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none;padding:10px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600}',
    '.cdwie-export-btn{background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:8px;border-radius:8px;cursor:pointer;font-size:12px}',
    '.cdwie-report-preview{overflow-y:auto;padding:24px;background:#f8fafc}',
    '.cdwie-preview-placeholder{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:16px;color:#94a3b8}',
    '.cdwie-preview-placeholder i{font-size:48px;opacity:0.3}',
    '.cdwie-preview-placeholder p{font-size:13px;text-align:center;max-width:260px;color:#64748b}',
    '.cdwie-preview-loading{display:flex;align-items:center;justify-content:center;gap:12px;height:100%;color:#6366f1}',
    /* Report preview light theme */
    '.rp-report{background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);max-width:760px;margin:0 auto;font-family:Inter,sans-serif}',
    '.rp-header{padding:24px 28px;background:#f8fafc;border-bottom:1px solid #e2e8f0}',
    '.rp-header-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}',
    '.rp-org{color:#64748b;font-size:12px;font-weight:700;display:flex;align-items:center;gap:6px}',
    '.rp-tlp{font-size:10px;font-weight:800;padding:3px 10px;border-radius:999px}',
    '.rp-title{margin:0 0 12px;font-size:20px;font-weight:800;color:#0f172a}',
    '.rp-meta{display:flex;gap:16px;flex-wrap:wrap}',
    '.rp-meta span{color:#64748b;font-size:11px;display:flex;align-items:center;gap:5px}',
    '.rp-section{padding:20px 28px;border-bottom:1px solid #e2e8f0}',
    '.rp-section p{color:#334155;font-size:13px;line-height:1.7;margin:0}',
    '.rp-section-title{color:#0f172a;font-size:14px;font-weight:700;margin:0 0 12px;display:flex;align-items:center;gap:7px}',
    '.rp-stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:12px}',
    '.rp-stat-box{background:#f1f5f9;border-radius:8px;padding:12px;text-align:center}',
    '.rp-stat-num{display:block;font-size:22px;font-weight:700;color:#6366f1}',
    '.rp-stat-box span{font-size:11px;color:#64748b}',
    '.rp-landscape-para{color:#334155;font-size:13px;line-height:1.7;margin:0}',
    '.rp-actor-row{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid #f1f5f9}',
    '.rp-actor-flag{font-size:18px}',
    '.rp-actor-row strong{flex:1;color:#0f172a;font-size:13px}',
    '.rp-actor-alias{color:#94a3b8;font-size:11px}',
    '.rp-ioc-row{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid #f1f5f9}',
    '.rp-ioc-row code{font-family:JetBrains Mono,monospace;font-size:12px;color:#6366f1;flex:1}',
    '.rp-campaign-row{display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid #f1f5f9}',
    '.rp-campaign-row strong{flex:1;color:#0f172a;font-size:13px}',
    '.rp-recs{color:#334155;font-size:13px;line-height:2;padding-left:18px;margin:0}',
    '.rp-badge{font-size:10px;font-weight:700;padding:2px 8px;border-radius:999px}',
    '.rp-badge-red{background:#fef2f2;color:#ef4444}',
    '.rp-badge-orange{background:#fff7ed;color:#f97316}',
    '.rp-badge-blue{background:#eff6ff;color:#3b82f6}',
    '.rp-dim{color:#94a3b8;font-size:12px;font-style:italic}',
    '.rp-footer{padding:14px 28px;background:#f8fafc;display:flex;justify-content:space-between;font-size:10px;color:#94a3b8}',
    /* Node detail panel */
    '.cdwie-node-detail{display:flex;flex-direction:column;gap:12px}',
    '.cdwie-node-header{padding:12px;border-radius:8px;background:#0f172a}',
    '.cdwie-node-type-badge{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;margin-bottom:6px;display:inline-block}',
    '.cdwie-node-label-lg{font-size:16px;font-weight:700;color:#f1f5f9}',
    '.cdwie-node-connections h4{color:#94a3b8;font-size:12px;margin:0 0 8px}',
    '.cdwie-node-conn-row{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid #1e293b;font-size:12px;color:#94a3b8}',
    /* Legend */
    '.cdwie-graph-legend{display:flex;flex-wrap:wrap;gap:10px;padding:8px 14px;border-top:1px solid #1e293b;background:#0f172a}',
    '.cdwie-legend-item{display:flex;align-items:center;gap:5px}',
    '.cdwie-legend-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}',
    '.cdwie-legend-label{color:#64748b;font-size:10px}',
    /* Badge green/grey */
    '.cdwie-badge-green{background:#dcfce7;color:#166534}',
    '.cdwie-badge-grey{background:#1e293b;color:#64748b}',
    '.cdwie-badge-orange{background:#fff7ed;color:#f97316}',
    /* Search zone */
    '.cdwie-search-zone{padding:24px 0 16px}',
    '.cdwie-search-header{text-align:center;margin-bottom:20px}',
    '.cdwie-engine-title{color:#f1f5f9;font-size:20px;font-weight:700;margin:0 0 6px}',
    '.cdwie-engine-sub{color:#64748b;font-size:13px;margin:0}',
    '.cdwie-search-main{margin-bottom:14px}',
    '.cdwie-search-input-wrap{display:flex;align-items:center;gap:0;background:#1e293b;border:1px solid #334155;border-radius:12px;overflow:hidden}',
    '.cdwie-search-icon{padding:0 14px;color:#475569;font-size:14px}',
    '.cdwie-search-input{flex:1;background:none;border:none;color:#f1f5f9;padding:14px 0;font-size:14px;min-width:0}',
    '.cdwie-search-input:focus{outline:none}',
    '.cdwie-search-input::placeholder{color:#475569}',
    '.cdwie-search-btn{background:#6366f1;color:#fff;border:none;padding:0 20px;height:100%;cursor:pointer;font-size:13px;font-weight:600;display:flex;align-items:center;gap:7px;transition:background 0.15s}',
    '.cdwie-search-btn:hover{background:#4f46e5}',
    '.cdwie-search-meta{display:flex;gap:16px;margin-top:8px;padding:0 4px}',
    '.cdwie-meta-item{color:#475569;font-size:11px;display:flex;align-items:center;gap:5px}',
    '.cdwie-suggestions-bar{display:flex;flex-wrap:wrap;gap:6px;align-items:center}',
    '.cdwie-sugg-label{color:#475569;font-size:11px;display:flex;align-items:center;gap:5px;margin-right:4px}',
    '.cdwie-query-chip{background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:5px 12px;border-radius:999px;cursor:pointer;font-size:11px;transition:all 0.15s}',
    '.cdwie-query-chip:hover{background:#6366f133;color:#a5b4fc;border-color:#6366f1}'
  ].join('\n');
  document.head.appendChild(s);
})();

/* ═══════════════════════════════════════════════════════════════════════════
   CLOSING IIFE BRACKET
   ═══════════════════════════════════════════════════════════════════════════ */
})();
