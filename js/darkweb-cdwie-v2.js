/**
 * ══════════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI v25.0 — Cognitive Dark Web Intelligence Engine (CDWIE) v2.0
 *  NEW:  Neural Correlator · Kill Chain Tracker · Dark Feed Live
 *  ENHANCED: Actor DNA v2 (timeline, attribution, live heatmap) · Predictive v2
 *            Knowledge Graph v2 · Deception v2 · Exec Reports v2
 *  FIXED: Activity Heatmap (SVG, live 30s polling) · Report builder (live data)
 *  REMOVED: CTI Copilot tab
 *  Entry point : window.renderDarkWeb()
 *  Namespace   : window._cdwiev2* / window._cdwieTab
 * ══════════════════════════════════════════════════════════════════════════════
 */
(function (global) {
'use strict';

/* ──────────────────────────── §1  CSS INJECTION ─────────────────────────── */
(function _css() {
  if (document.getElementById('cdwie-v2-css')) return;
  var lk = document.createElement('link');
  lk.id = 'cdwie-v2-css'; lk.rel = 'stylesheet';
  lk.href = 'css/darkweb-cdwie-v2.css';
  document.head.appendChild(lk);
  /* Runtime critical overrides */
  var s = document.createElement('style');
  s.id = 'cdwie-v2-runtime';
  s.textContent = [
    '#cdwie-engine-panel .v2-engine{display:block!important}',
    '.v2-spinner{width:28px;height:28px;border:3px solid #1e293b;border-top-color:#6366f1;border-radius:50%;animation:v2spin .8s linear infinite}',
    '@keyframes v2spin{to{transform:rotate(360deg)}}',
    '.v2-loading{display:flex;flex-direction:column;align-items:center;gap:16px;padding:60px 0}',
    '.v2-ws-dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#475569;transition:background .4s}',
    '.v2-ws-dot.connected{background:#22c55e;box-shadow:0 0 6px #22c55e88}',
    '.v2-ws-dot.disconnected{background:#ef4444}',
    '.v2-stale-warn{display:none;align-items:center;gap:6px;font-size:11px;color:#f97316;padding:2px 8px;border-radius:4px;background:#f9731620}',
    '.v2-heatmap-wrap{width:100%;overflow-x:auto}',
    '.v2-heatmap-header{display:flex;align-items:center;gap:4px;margin-bottom:6px;flex-wrap:wrap}',
    '.v2-heatmap-tooltip{z-index:9999!important}',
    '.v2-engine{animation:v2fadeIn .25s ease}',
    '@keyframes v2fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}',
  ].join('');
  document.head.appendChild(s);
})();

/* ──────────────────────────── §2  ACTOR DATA STORE ──────────────────────── */
var DW2_ACTORS = {
  apt29: {
    id:'apt29',name:'APT29',alias:'Cozy Bear',
    aliases:['CozyDuke','The Dukes','Midnight Blizzard','YTTRIUM','Iron Hemlock'],
    origin:'Russia',sponsor:'SVR (Foreign Intelligence Service)',
    active:'2008\u2013Present',confidence:94,threat:'CRITICAL',color:'#ef4444',flag:'\ud83c\uddf7\ud83c\uddfa',
    faIcon:'fa-eye',
    sectors:['Government','Defense','Think Tanks','Energy','Healthcare'],
    ttps:['T1566.001','T1059.001','T1078','T1021.002','T1083','T1027','T1036','T1057','T1055','T1102'],
    tools:['HAMMERTOSS','MiniDuke','CosmicDuke','FatDuke','BEATDROP','BEACON','WellMess'],
    desc:'APT29 (Cozy Bear) is sponsored by Russia\u2019s SVR. Responsible for SUNBURST/SolarWinds supply-chain compromise affecting 18,000+ orgs. Hallmarks: living-off-the-land, long-term persistence, near-zero forensic footprint.',
    behavior:{sophistication:96,persistence:92,stealth:95,speed:45,scale:38,evasion:97,innovation:88,destructiveness:30},
    infra:{asns:['AS31898','AS16509','AS14618'],hostingProviders:['Amazon AWS','Microsoft Azure','Cloudflare'],c2Domains:['*.azurewebsites.net','*.blob.core.windows.net']},
    opHours:'Tue\u2013Sat 08:00\u201319:00 MSK',writingStyle:'Technical formal Russian syntax. Heavy LOLBins usage.',
    fingerprintScore:94,ttpDriftDetected:false,
    attributionSignals:[
      {label:'Infrastructure',weight:35,score:97},
      {label:'TTP Match',weight:30,score:96},
      {label:'Geolocation',weight:20,score:88},
      {label:'Language Analysis',weight:15,score:91}
    ],
    timeline:[
      {date:'2008',event:'Group formed \u2014 early spear-phishing vs. government targets'},
      {date:'2014',event:'MiniDuke campaign \u2014 targeting NATO members'},
      {date:'2016',event:'DNC breach \u2014 US election interference'},
      {date:'2019',event:'WellMess \u2014 COVID-19 vaccine research theft'},
      {date:'2020',event:'SUNBURST \u2014 SolarWinds supply-chain (18,000 orgs)'},
      {date:'2021',event:'BEATDROP/BEACON \u2014 Azure AD exploitation campaign'},
      {date:'2023',event:'Midnight Blizzard rebranding \u2014 Outlook 0-day CVE-2023-23397'},
      {date:'2024',event:'HAMMERTOSS v4 deployed \u2014 EU network ranges'},
      {date:'2025',event:'WINTER STORM campaign \u2014 ACTIVE, high confidence'}
    ]
  },
  lockbit: {
    id:'lockbit',name:'LockBit 4.0',alias:'LockBit Group',
    aliases:['LockBit Black','LockBit Green','LockBitSupp'],
    origin:'Russia (suspected)',sponsor:'Criminal / RaaS',
    active:'2019\u2013Present',confidence:91,threat:'CRITICAL',color:'#f97316',flag:'\ud83c\udf10',
    faIcon:'fa-lock',
    sectors:['Healthcare','Finance','Manufacturing','Government','Legal'],
    ttps:['T1486','T1490','T1083','T1489','T1562','T1078','T1021','T1003','T1047'],
    tools:['LockBit 4.0','StealBit','Mimikatz','Cobalt Strike','Rclone'],
    desc:'World\u2019s most prolific RaaS. LockBit 4.0 features advanced affiliate programs, auto-encryption, triple extortion. 1,700+ claimed victims globally.',
    behavior:{sophistication:88,persistence:78,stealth:72,speed:95,scale:98,evasion:80,innovation:85,destructiveness:95},
    infra:{asns:['AS44477','AS208091'],hostingProviders:['Bulletproof (RU)','Shinjiru'],c2Domains:['lockbit4.onion','lockbitapt.onion']},
    opHours:'Mon\u2013Sun 00:00\u201323:59 UTC (automated)',writingStyle:'Professional business tone. English + Russian.',
    fingerprintScore:88,ttpDriftDetected:true,
    attributionSignals:[
      {label:'Infrastructure',weight:30,score:91},
      {label:'TTP Match',weight:35,score:94},
      {label:'Geolocation',weight:15,score:72},
      {label:'Language Analysis',weight:20,score:85}
    ],
    timeline:[
      {date:'2019',event:'LockBit 1.0 \u2014 first samples in wild'},
      {date:'2021',event:'LockBit 2.0 \u2014 StealBit exfil tool introduced'},
      {date:'2022',event:'LockBit 3.0 (Black) \u2014 bug bounty program launched'},
      {date:'2023',event:'FBI Operation Cronos \u2014 infrastructure seized'},
      {date:'2024',event:'LockBit 4.0 \u2014 relaunched, 500+ new victims'},
      {date:'2025',event:'IRON RANSOM campaign \u2014 ACTIVE, 91% escalation probability'}
    ]
  },
  apt41: {
    id:'apt41',name:'APT41',alias:'Double Dragon',
    aliases:['Winnti','Barium','Wicked Panda','Earth Baku'],
    origin:'China',sponsor:'MSS (Ministry of State Security)',
    active:'2012\u2013Present',confidence:89,threat:'HIGH',color:'#a855f7',flag:'\ud83c\udde8\ud83c\uddf3',
    faIcon:'fa-dragon',
    sectors:['Technology','Healthcare','Telecom','Finance','Gaming'],
    ttps:['T1190','T1059.003','T1053.005','T1027','T1140','T1070','T1055.001','T1071'],
    tools:['CROSSWALK','POISONPLUG','ShadowPad','Cobalt Strike','njRAT','PlugX','KeyPlug'],
    desc:'APT41 uniquely conducts both nation-state espionage and financially motivated intrusions. Targets pharma for IP theft, gaming for financial gain, governments for intel.',
    behavior:{sophistication:91,persistence:87,stealth:85,speed:72,scale:82,evasion:89,innovation:90,destructiveness:60},
    infra:{asns:['AS4812','AS7497','AS23650'],hostingProviders:['China Telecom','Alibaba Cloud'],c2Domains:['*.microsoftonline-portal.com','update.microsoft.*.com']},
    opHours:'Mon\u2013Fri 09:00\u201318:00 CST',writingStyle:'Mandarin influence in code comments. Traditional + simplified Chinese.',
    fingerprintScore:91,ttpDriftDetected:false,
    attributionSignals:[
      {label:'Infrastructure',weight:35,score:89},
      {label:'TTP Match',weight:30,score:92},
      {label:'Geolocation',weight:20,score:85},
      {label:'Language Analysis',weight:15,score:88}
    ],
    timeline:[
      {date:'2012',event:'Group formation \u2014 dual espionage + financial mandate'},
      {date:'2017',event:'Winnti supply-chain attacks on gaming companies'},
      {date:'2020',event:'ShadowPad \u2014 MSP supply-chain compromise'},
      {date:'2022',event:'Earth Baku \u2014 APAC government targeting'},
      {date:'2024',event:'KeyPlug v2 \u2014 new TLS fingerprint evasion'},
      {date:'2025',event:'DRAGONFLY III \u2014 ACTIVE, 48% escalation probability'}
    ]
  },
  fin7: {
    id:'fin7',name:'FIN7',alias:'Carbanak',
    aliases:['Carbanak Group','Navigator Group','ITG14','Carbon Spider'],
    origin:'Ukraine/Russia',sponsor:'Criminal / Financial',
    active:'2013\u2013Present',confidence:88,threat:'CRITICAL',color:'#eab308',flag:'\ud83c\udf10',
    faIcon:'fa-dollar-sign',
    sectors:['Finance','Retail','Hospitality','Healthcare','Technology'],
    ttps:['T1566','T1059.007','T1203','T1021.006','T1056.001','T1110','T1539'],
    tools:['CARBANAK','GRIFFON','BOOSTWRITE','RDFSNIFFER','Cobalt Strike','PowerShell Empire'],
    desc:'FIN7 responsible for billions in losses. Pioneered fake \u201cCombi Security\u201d front company for pentest recruitment. Specialises in POS malware and BEC.',
    behavior:{sophistication:87,persistence:82,stealth:88,speed:68,scale:75,evasion:85,innovation:78,destructiveness:50},
    infra:{asns:['AS44050','AS199524'],hostingProviders:['Frantech','BuyVM'],c2Domains:['payment-process.*.net','*.shopify.com.*.xyz']},
    opHours:'Mon\u2013Fri 08:00\u201320:00 EET',writingStyle:'English with Ukrainian syntax. Business terminology.',
    fingerprintScore:85,ttpDriftDetected:true,
    attributionSignals:[
      {label:'Infrastructure',weight:30,score:88},
      {label:'TTP Match',weight:35,score:87},
      {label:'Geolocation',weight:20,score:82},
      {label:'Language Analysis',weight:15,score:90}
    ],
    timeline:[
      {date:'2013',event:'CARBANAK banking trojan \u2014 attacks on financial institutions'},
      {date:'2015',event:'$1B stolen from 100+ banks across 30 countries'},
      {date:'2018',event:'Combi Security front company exposed by FBI'},
      {date:'2021',event:'GRIFFON JS implant \u2014 fileless persistence'},
      {date:'2023',event:'Cl0p partnership \u2014 MFT supply-chain exploitation'},
      {date:'2025',event:'SILENT RANSOM campaign \u2014 ACTIVE, 67% escalation probability'}
    ]
  },
  oilrig: {
    id:'oilrig',name:'OilRig',alias:'APT34',
    aliases:['APT34','Helix Kitten','Lyceum','Crambus'],
    origin:'Iran',sponsor:'MOIS (Ministry of Intelligence)',
    active:'2014\u2013Present',confidence:86,threat:'HIGH',color:'#22d3ee',flag:'\ud83c\uddee\ud83c\uddf7',
    faIcon:'fa-oil-can',
    sectors:['Energy','Government','Finance','Telecom','Aviation'],
    ttps:['T1190','T1566.001','T1078','T1505.003','T1071.001','T1041','T1059.004'],
    tools:['QUADAGENT','POSHC2','DNSpionage','RDAT','Karkoff','SideTwist','Marlin'],
    desc:'OilRig (APT34) targets Middle Eastern nations. Known for DNS tunneling C2 and watering-hole attacks. Persistent access for long-term intelligence gathering.',
    behavior:{sophistication:82,persistence:88,stealth:80,speed:55,scale:60,evasion:79,innovation:75,destructiveness:45},
    infra:{asns:['AS44244','AS48159','AS12880'],hostingProviders:['Pars Online','Shatel','TIC'],c2Domains:['*.*.ir','news-portal.*.net']},
    opHours:'Sun\u2013Thu 08:00\u201317:00 IRST',writingStyle:'Farsi influence. Mix of Farsi and English.',
    fingerprintScore:82,ttpDriftDetected:false,
    attributionSignals:[
      {label:'Infrastructure',weight:35,score:86},
      {label:'TTP Match',weight:30,score:83},
      {label:'Geolocation',weight:20,score:90},
      {label:'Language Analysis',weight:15,score:88}
    ],
    timeline:[
      {date:'2014',event:'Group formation \u2014 Iranian government cyber arm'},
      {date:'2017',event:'DNSpionage \u2014 DNS tunneling C2 vs Lebanese government'},
      {date:'2019',event:'RDAT \u2014 email C2 over Exchange Web Services'},
      {date:'2021',event:'Marlin implant \u2014 aviation sector targeting'},
      {date:'2023',event:'SideTwist update \u2014 OPSEC-hardened C2'},
      {date:'2025',event:'Energy sector scanning elevated \u2014 monitoring'}
    ]
  },
  lazarus: {
    id:'lazarus',name:'Lazarus Group',alias:'Hidden Cobra',
    aliases:['Hidden Cobra','Guardians of Peace','APT38','Zinc'],
    origin:'North Korea',sponsor:'RGB (Reconnaissance General Bureau)',
    active:'2009\u2013Present',confidence:93,threat:'CRITICAL',color:'#ec4899',flag:'\ud83c\uddf0\ud83c\uddf5',
    faIcon:'fa-skull-crossbones',
    sectors:['Finance','Cryptocurrency','Defense','Aerospace','Government'],
    ttps:['T1566','T1059.003','T1053','T1070','T1485','T1486','T1552','T1041'],
    tools:['HOPLIGHT','BLINDINGCAN','BADCALL','AppleJeus','DRATzarus','FALLCHILL','ELECTRICFISH'],
    desc:'Lazarus responsible for the largest crypto heists in history ($625M Ronin Network). Funds regime weapons programs. Also conducts destructive wiper attacks.',
    behavior:{sophistication:90,persistence:85,stealth:78,speed:65,scale:70,evasion:82,innovation:86,destructiveness:88},
    infra:{asns:['AS131279','AS17379'],hostingProviders:['KCC','Choson Exchange'],c2Domains:['blockchain-update.*.com','*.*.kp']},
    opHours:'Mon\u2013Sat 01:00\u201315:00 KST (irregular)',writingStyle:'Korean syntax in code. English operational comms.',
    fingerprintScore:90,ttpDriftDetected:false,
    attributionSignals:[
      {label:'Infrastructure',weight:30,score:93},
      {label:'TTP Match',weight:35,score:92},
      {label:'Geolocation',weight:20,score:88},
      {label:'Language Analysis',weight:15,score:94}
    ],
    timeline:[
      {date:'2009',event:'Dark Seoul \u2014 DDoS vs South Korean government'},
      {date:'2014',event:'Sony Pictures hack \u2014 destructive wiper malware'},
      {date:'2016',event:'Bangladesh Bank heist \u2014 $81M stolen via SWIFT'},
      {date:'2019',event:'AppleJeus \u2014 macOS crypto exchange backdoor'},
      {date:'2022',event:'Ronin bridge \u2014 $625M stolen, largest crypto theft'},
      {date:'2023',event:'Atomic Wallet \u2014 $100M stolen, supply-chain attack'},
      {date:'2025',event:'DeFi protocol targeting elevated \u2014 active monitoring'}
    ]
  },
  blackcat: {
    id:'blackcat',name:'BlackCat/ALPHV',alias:'ALPHV Group',
    aliases:['ALPHV','Noberus','BlackCat Ransomware Gang'],
    origin:'Unknown (ex-DarkSide)',sponsor:'Criminal / RaaS',
    active:'2021\u2013Present',confidence:87,threat:'CRITICAL',color:'#8b5cf6',flag:'\ud83c\udf10',
    faIcon:'fa-cat',
    sectors:['Healthcare','Legal','Energy','Manufacturing','Finance'],
    ttps:['T1486','T1657','T1562','T1190','T1059.001','T1078','T1021.001','T1567'],
    tools:['BlackCat Ransomware','ExMatter','Cobalt Strike','BurntCigar','Conti Toolkit'],
    desc:'BlackCat/ALPHV runs the first Rust-written ransomware enabling cross-platform attacks. Triple-extortion model. Survived FBI seizure Dec 2023, relaunched days later.',
    behavior:{sophistication:89,persistence:80,stealth:77,speed:88,scale:85,evasion:83,innovation:92,destructiveness:90},
    infra:{asns:['AS60068','AS206092'],hostingProviders:['Bulletproof (RU/RO)'],c2Domains:['alphv*.onion','blackcat*.onion']},
    opHours:'Mon\u2013Sun (affiliate-operated, 24/7)',writingStyle:'Professional business communication. English primary.',
    fingerprintScore:87,ttpDriftDetected:false,
    attributionSignals:[
      {label:'Infrastructure',weight:35,score:87},
      {label:'TTP Match',weight:30,score:89},
      {label:'Geolocation',weight:20,score:75},
      {label:'Language Analysis',weight:15,score:82}
    ],
    timeline:[
      {date:'2021',event:'ALPHV launch \u2014 first Rust-based ransomware'},
      {date:'2022',event:'Triple extortion \u2014 DDoS added as 3rd pressure tactic'},
      {date:'2023',event:'FBI seizure \u2014 infrastructure takedown, decryptor released'},
      {date:'2023',event:'Relaunch \u2014 $22M ransom claim from Change Healthcare'},
      {date:'2024',event:'Change Healthcare attack \u2014 US healthcare system disrupted'},
      {date:'2025',event:'Healthcare sector targeting elevated \u2014 active monitoring'}
    ]
  }
};

/* ──────────────────────────── §3  CAMPAIGN DATA ─────────────────────────── */
var DW2_CAMPAIGNS = [
  {
    id:'iron-ransom',name:'IRON RANSOM',group:'LockBit 4.0',prob:91,eta:'1\u20133 days',confidence:'CRITICAL',
    currentStage:4,
    stages:[
      {id:0,name:'Reconnaissance',phase:'recon',confirmed:true,ttps:['T1595'],eta:'Complete'},
      {id:1,name:'Initial Access',phase:'initial',confirmed:true,ttps:['T1190','T1133'],eta:'Complete'},
      {id:2,name:'Execution',phase:'exec',confirmed:true,ttps:['T1059.003'],eta:'Complete'},
      {id:3,name:'Persistence',phase:'persist',confirmed:true,ttps:['T1078'],eta:'Complete'},
      {id:4,name:'Lateral Movement',phase:'lateral',confirmed:true,ttps:['T1021','T1570'],eta:'CURRENT'},
      {id:5,name:'Exfiltration/Ransom',phase:'exfil',confirmed:false,ttps:['T1486','T1490'],eta:'~36 hours',prob:91}
    ],
    defenses:['ISOLATE affected segments NOW \u2014 lateral movement confirmed','Snapshot all critical VMs immediately','Engage IR team \u2014 deploy StealBit IOCs to SIEM']
  },
  {
    id:'winter-storm',name:'WINTER STORM',group:'APT29',prob:73,eta:'6\u201312 days',confidence:'HIGH',
    currentStage:3,
    stages:[
      {id:0,name:'Reconnaissance',phase:'recon',confirmed:true,ttps:['T1595','T1598'],eta:'Complete'},
      {id:1,name:'Initial Access',phase:'initial',confirmed:true,ttps:['T1566.001','T1078'],eta:'Complete'},
      {id:2,name:'Execution',phase:'exec',confirmed:true,ttps:['T1059.001','T1047'],eta:'Complete'},
      {id:3,name:'Persistence',phase:'persist',confirmed:true,ttps:['T1547','T1053.005'],eta:'CURRENT'},
      {id:4,name:'Lateral Movement',phase:'lateral',confirmed:false,ttps:['T1021.002','T1080'],eta:'~3 days',prob:68},
      {id:5,name:'Exfiltration',phase:'exfil',confirmed:false,ttps:['T1041','T1048'],eta:'~8 days',prob:44}
    ],
    defenses:['Deploy EDR behavioral rules for WMI persistence (T1047)','Block lateral SMB with host-based firewall','Enable MFA on all admin accounts immediately']
  },
  {
    id:'silent-ransom',name:'SILENT RANSOM',group:'FIN7',prob:67,eta:'4\u20138 days',confidence:'HIGH',
    currentStage:2,
    stages:[
      {id:0,name:'Reconnaissance',phase:'recon',confirmed:true,ttps:['T1598'],eta:'Complete'},
      {id:1,name:'Phishing',phase:'initial',confirmed:true,ttps:['T1566'],eta:'Complete'},
      {id:2,name:'Execution',phase:'exec',confirmed:true,ttps:['T1059.007'],eta:'CURRENT'},
      {id:3,name:'Persistence',phase:'persist',confirmed:false,ttps:['T1547'],eta:'~2 days',prob:72},
      {id:4,name:'Data Staging',phase:'lateral',confirmed:false,ttps:['T1074','T1560'],eta:'~5 days',prob:58},
      {id:5,name:'Exfiltration',phase:'exfil',confirmed:false,ttps:['T1041','T1048'],eta:'~8 days',prob:46}
    ],
    defenses:['Block GRIFFON JS execution via AppLocker','Review email gateway for CARBANAK lure templates','Audit service accounts for unusual scripting activity']
  },
  {
    id:'dragonfly3',name:'DRAGONFLY III',group:'APT41',prob:48,eta:'14\u201321 days',confidence:'MEDIUM',
    currentStage:1,
    stages:[
      {id:0,name:'Reconnaissance',phase:'recon',confirmed:true,ttps:['T1595','T1592'],eta:'Complete'},
      {id:1,name:'Initial Access',phase:'initial',confirmed:true,ttps:['T1190'],eta:'CURRENT'},
      {id:2,name:'Execution',phase:'exec',confirmed:false,ttps:['T1059.003'],eta:'~5 days',prob:55},
      {id:3,name:'Persistence',phase:'persist',confirmed:false,ttps:['T1053.005'],eta:'~9 days',prob:48},
      {id:4,name:'Collection',phase:'lateral',confirmed:false,ttps:['T1560','T1074'],eta:'~14 days',prob:38},
      {id:5,name:'Exfiltration',phase:'exfil',confirmed:false,ttps:['T1041'],eta:'~21 days',prob:30}
    ],
    defenses:['Patch CVE-2024-21887 (Ivanti) on internet-facing appliances','Enable enhanced logging on web application servers','Review recent auth logs for anomalous access patterns']
  }
];

/* ──────────────────────────── §4  NEURAL CORRELATIONS ───────────────────── */
var DW2_CORRELATIONS = [
  {id:'c1',source:'lockbit',target:'blackcat',score:88,type:'tooling',shared:['Cobalt Strike beacon watermark match','ExMatter exfil tool overlap'],ttps:['T1486','T1490','T1078']},
  {id:'c2',source:'apt29',target:'apt41',score:72,type:'infra',shared:['AS16509 (AWS) shared','*.azurewebsites.net pattern','C2 rotation timing'],ttps:['T1078','T1036','T1055']},
  {id:'c3',source:'fin7',target:'lockbit',score:65,type:'ttp',shared:['GRIFFON/PowerShell overlap (T1059.007)','WinRM lateral movement','Access broker overlap'],ttps:['T1059','T1021','T1566']},
  {id:'c4',source:'blackcat',target:'fin7',score:61,type:'tooling',shared:['Cobalt Strike beacon','Mimikatz fork','TG access broker channel'],ttps:['T1003','T1078','T1486']},
  {id:'c5',source:'lazarus',target:'apt41',score:58,type:'behavioral',shared:['Crypto exchange targeting overlap','Supply-chain injection pattern'],ttps:['T1195','T1552','T1041']},
  {id:'c6',source:'oilrig',target:'apt29',score:49,type:'ttp',shared:['DNS tunneling C2 (T1071.001)','App Layer Protocol'],ttps:['T1071','T1041','T1078']},
  {id:'c7',source:'apt29',target:'lazarus',score:41,type:'infra',shared:['Cloud provider overlap (AWS us-east-1)'],ttps:['T1078','T1059']},
  {id:'c8',source:'apt41',target:'oilrig',score:44,type:'behavioral',shared:['Watering-hole staging overlap','Server-side webshells (T1505.003)'],ttps:['T1505','T1190','T1059']}
];

/* ──────────────────────────── §5  LIVE FEED SEEDS ───────────────────────── */
var DW2_FEED_SEED = [
  {actor:'LockBit 4.0',campaign:'IRON RANSOM',type:'ransomware',sev:95,source:'darkforum.onion',iocs:['lockbit4[.]onion','195.54.162.88'],summary:'New victim: Regional hospital network. 2.1TB claimed. 48h payment deadline.'},
  {actor:'APT29',campaign:'WINTER STORM',type:'apt',sev:88,source:'paste.onion',iocs:['svr-proxy[.]net','40.127.235.1'],summary:'HAMMERTOSS v4 C2 beacons. New EU targets \u2014 3 government ministries.'},
  {actor:'Unknown',campaign:null,type:'credential',sev:72,source:'breachforum.st',iocs:['combolist_2025_v7.txt'],summary:'850K credential combo \u2014 healthcare + finance sector. Lumma Stealer v5 suspected.'},
  {actor:'Lazarus Group',campaign:null,type:'crypto',sev:84,source:'telegram-monitor',iocs:['bc1q9f2a6wk5xp...','0x7a2b4c...'],summary:'AppleJeus variant targeting DeFi SDKs. Trojanized npm package detected.'},
  {actor:'FIN7',campaign:'SILENT RANSOM',type:'exploit',sev:79,source:'darkforum.onion',iocs:['GRIFFON.js.b64','payment-process[.]net'],summary:'GRIFFON v4 in affiliate channel. New evasion: AMSI bypass via COM hijack.'},
  {actor:'BlackCat',campaign:null,type:'ransomware',sev:91,source:'alphv.onion',iocs:['blackcat*.onion','ExMatter_v4.exe'],summary:'New victim: US legal firm. 800GB legal docs. $12M demand.'},
  {actor:'APT41',campaign:'DRAGONFLY III',type:'apt',sev:66,source:'paste.onion',iocs:['update.microsoft.*.com','ShadowPad_cfg.bin'],summary:'ShadowPad loader update \u2014 new TLS fingerprint, targets telecom API gateways.'},
  {actor:'Unknown',campaign:null,type:'recruitment',sev:45,source:'xss.is',iocs:[],summary:'RaaS affiliate recruitment \u2014 80% split, English-speaking operators preferred.'},
  {actor:'OilRig',campaign:null,type:'apt',sev:63,source:'telegram-monitor',iocs:['news-portal[.]net','RDAT_v3.bin'],summary:'RDAT v3 \u2014 EWS C2 over TLS, targeting GCC energy sector.'},
  {actor:'Unknown',campaign:null,type:'credential',sev:58,source:'breachforum.st',iocs:['420K_gov_combo_2025.txt'],summary:'420K government email credentials. Mostly .gov.uk and .gov.au domains.'}
];

/* ──────────────────────────── §6  MODULE STATE ──────────────────────────── */
var _s = {
  activeTab:'cognitive-search',
  actor:{selected:'apt29',dnaTab:'overview'},
  graph:{nodes:[],edges:[],scale:1,offsetX:0,offsetY:0,dragNode:null,animFrame:null,initialized:false},
  search:{results:[],query:'',running:false},
  report:{type:'executive',timeframe:'7d',sector:'all',tlp:'amber',generating:false,generated:false,version:0,
    sections:{exec_summary:true,threat_landscape:true,actor_profiles:true,ioc_list:true,campaign_analysis:true,recommendations:true,appendix:false}},
  correlator:{selectedEdge:null},
  killchain:{selectedCampaign:'iron-ransom'},
  darkfeed:{entries:[],paused:false,filter:{actor:'all',type:'all',sev:0},lastId:0},
  heatmap:{data:{},polling:{}},
  kpis:{queries:3247,actors:Object.keys({apt29:1,lockbit:1,apt41:1,fin7:1,oilrig:1,lazarus:1,blackcat:1}).length+82,nodes:1432,threats:34,credibility:81,briefed:12,reports:7},
  lastUpdated:Date.now()
};

/* ──────────────────────────── §7  UTILITIES ─────────────────────────────── */
function _e(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function _rand(a,b){return Math.floor(Math.random()*(b-a+1))+a;}
function _clamp(v,a,b){return Math.max(a,Math.min(b,v));}
function _el(tag,cls,html){var e=document.createElement(tag||'div');if(cls)e.className=cls;if(html!==undefined)e.innerHTML=html;return e;}
function _qs(s,c){return(c||document).querySelector(s);}
function _qsa(s,c){return Array.from((c||document).querySelectorAll(s));}
function _ago(ts){var d=(Date.now()-ts)/1000;if(d<5)return'just now';if(d<60)return Math.floor(d)+'s ago';if(d<3600)return Math.floor(d/60)+'m ago';return Math.floor(d/3600)+'h ago';}
function _badge(level,text){var m={CRITICAL:'v2-badge-critical',HIGH:'v2-badge-high',MEDIUM:'v2-badge-medium',LOW:'v2-badge-low'};return'<span class="v2-badge '+(m[level]||'v2-badge-blue')+'">'+_e(text||level)+'</span>';}
function _countUp(el,target,dur){if(!el)return;var start=0,step=16,inc=target/((dur||900)/step);var t=setInterval(function(){start=Math.min(start+inc,target);el.textContent=Math.floor(start).toLocaleString();if(start>=target)clearInterval(t);},step);}
function _flipNum(el,n){if(!el)return;el.style.transform='translateY(-8px)';el.style.opacity='0';setTimeout(function(){el.textContent=n.toLocaleString();el.style.transform='';el.style.opacity='1';},200);}
function _toast(msg,type){if(typeof window._toast==='function'){window._toast(msg,type||'info');}else{console.log('[CDWIEv2] '+msg);}}

/* heatmap data generator */
function _genHeatmapData(actor){
  var m=actor.opHours?actor.opHours.match(/(\d{2}):00[^\d]+(\d{2}):00/):null;
  var startH=m?parseInt(m[1]):8,endH=m?parseInt(m[2]):18;
  var isWd=actor.opHours&&(actor.opHours.includes('Mon\u2013Fri')||actor.opHours.includes('Tue\u2013Sat'));
  var isSR=actor.opHours&&actor.opHours.includes('Sun\u2013Thu');
  var hc=(actor.color||'#6366f1').replace('#','');
  var rgb=parseInt(hc.substr(0,2),16)+','+parseInt(hc.substr(2,2),16)+','+parseInt(hc.substr(4,2),16);
  var data=[];
  for(var d=0;d<7;d++){
    var row=[];
    for(var h=0;h<24;h++){
      var base=Math.random();
      if(endH>startH)base=(h>=startH&&h<=endH)?base*0.85+0.15:base*0.10;
      if(isWd&&(d===5||d===6))base*=0.07;
      if(isSR&&d===6)base*=0.04;
      base=_clamp(base+(Math.random()-0.5)*0.08,0.02,1);
      row.push(parseFloat(base.toFixed(3)));
    }
    data.push(row);
  }
  return{matrix:data,rgb:rgb};
}

/* ──────────────────────────── §8  LIVE SIMULATION ───────────────────────── */
var _simTimer=null;
function _startSimulation(){
  if(_simTimer)return;
  _simTimer=setInterval(function(){
    if(_s.darkfeed.paused)return;
    var seed=DW2_FEED_SEED[_rand(0,DW2_FEED_SEED.length-1)];
    var entry={id:++_s.darkfeed.lastId,ts:Date.now(),actor:seed.actor,campaign:seed.campaign,
      type:seed.type,sev:_clamp(seed.sev+_rand(-8,8),10,100),source:seed.source,iocs:seed.iocs,summary:seed.summary};
    _s.darkfeed.entries.unshift(entry);
    if(_s.darkfeed.entries.length>200)_s.darkfeed.entries.pop();
    _s.lastUpdated=Date.now();
    /* inject into live feed panel if visible */
    var feedEl=document.getElementById('v2-darkfeed-list');
    if(feedEl&&!_s.darkfeed.paused)_prependFeedEntry(feedEl,entry);
  },_rand(3500,9000));
}

/* ──────────────────────────── §9  HEATMAP ENGINE ────────────────────────── */
function _startHeatmapPolling(actorId){
  var actor=DW2_ACTORS[actorId];if(!actor)return;
  if(!_s.heatmap.data[actorId])_s.heatmap.data[actorId]=_genHeatmapData(actor);
  if(_s.heatmap.polling[actorId])return;
  _s.heatmap.polling[actorId]=setInterval(function(){
    var d=_rand(0,6),h=_rand(0,23);
    var existing=_s.heatmap.data[actorId];if(!existing)return;
    existing.matrix[d][h]=_clamp(existing.matrix[d][h]+(Math.random()-0.5)*0.15,0.02,1);
    var heatEl=document.getElementById('cdwie-heatmap-'+actorId);
    if(heatEl)_renderHeatmapSVG(actorId,heatEl);
    _s.lastUpdated=Date.now();
  },30000);
}

function _renderHeatmapSVG(actorId,container){
  container.innerHTML='';
  var actor=DW2_ACTORS[actorId];if(!actor)return;
  if(!_s.heatmap.data[actorId])_s.heatmap.data[actorId]=_genHeatmapData(actor);
  var hd=_s.heatmap.data[actorId];
  var DAYS=['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  var CW=14,CH=14,GAP=2,LEFT=30,TOP=20;
  var W=LEFT+(CW+GAP)*24+8,H=TOP+(CH+GAP)*7+28;
  var parts=hd.rgb.split(',').map(Number);
  function cellColor(a){
    var bg=[10,14,26];
    return'rgb('+Math.round(bg[0]+(parts[0]-bg[0])*a)+','+Math.round(bg[1]+(parts[1]-bg[1])*a)+','+Math.round(bg[2]+(parts[2]-bg[2])*a)+')';
  }
  /* header */
  var hdr=_el('div','v2-heatmap-header');
  hdr.innerHTML='<span class="v2-ws-dot connected"></span><span style="color:#94a3b8;font-size:11px;margin-left:5px">Live \u00b7 30s refresh</span>'+
    '<span style="margin-left:auto;color:#475569;font-size:10px">'+_e(actor.opHours)+'</span>';
  container.appendChild(hdr);
  /* svg */
  var NS='http://www.w3.org/2000/svg';
  var svg=document.createElementNS(NS,'svg');
  svg.setAttribute('width',W);svg.setAttribute('height',H);
  svg.style.cssText='display:block;overflow:visible';
  /* tooltip */
  var tooltip=_el('div','v2-heatmap-tooltip');
  tooltip.style.cssText='display:none;position:fixed;z-index:9999;pointer-events:none;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:8px 12px;font-size:12px;color:#f1f5f9;box-shadow:0 4px 24px rgba(0,0,0,.6)';
  document.body.appendChild(tooltip);
  /* hour axis */
  for(var hx=0;hx<24;hx++){if(hx%4===0){var ht=document.createElementNS(NS,'text');ht.setAttribute('x',LEFT+(CW+GAP)*hx+CW/2);ht.setAttribute('y',TOP-5);ht.setAttribute('text-anchor','middle');ht.setAttribute('fill','#475569');ht.setAttribute('font-size','9');ht.textContent=hx+'h';svg.appendChild(ht);}}
  /* cells */
  for(var dd=0;dd<7;dd++){
    var dl=document.createElementNS(NS,'text');dl.setAttribute('x',LEFT-4);dl.setAttribute('y',TOP+(CH+GAP)*dd+CH/2+3);dl.setAttribute('text-anchor','end');dl.setAttribute('fill','#475569');dl.setAttribute('font-size','9');dl.textContent=DAYS[dd];svg.appendChild(dl);
    for(var hh=0;hh<24;hh++){
      (function(d2,h2){
        var alpha=hd.matrix[d2][h2];var count=Math.round(alpha*142);
        var rect=document.createElementNS(NS,'rect');
        rect.setAttribute('x',LEFT+(CW+GAP)*h2);rect.setAttribute('y',TOP+(CH+GAP)*d2);
        rect.setAttribute('width',CW);rect.setAttribute('height',CH);rect.setAttribute('rx','2');
        rect.setAttribute('fill',cellColor(alpha));rect.style.cursor='pointer';rect.style.transition='opacity .15s';
        rect.addEventListener('mouseenter',function(ev){
          rect.setAttribute('opacity','0.7');tooltip.style.display='block';
          tooltip.innerHTML='<strong>'+DAYS[d2]+' '+String(h2).padStart(2,'0')+':00 UTC</strong><br>'+
            '<span style="color:#'+parts[0].toString(16).padStart(2,'0')+parts[1].toString(16).padStart(2,'0')+parts[2].toString(16).padStart(2,'0')+'">'+count+'</span> events \u00b7 '+
            (count>80?'<span style="color:#ef4444">HIGH</span>':count>40?'<span style="color:#f97316">MEDIUM</span>':'<span style="color:#22c55e">LOW</span>')+' activity';
          var r=ev.target.getBoundingClientRect();tooltip.style.left=(r.right+8)+'px';tooltip.style.top=(r.top-4)+'px';
        });
        rect.addEventListener('mouseleave',function(){rect.setAttribute('opacity','1');tooltip.style.display='none';});
        svg.appendChild(rect);
      })(dd,hh);
    }
  }
  /* legend */
  var ly=TOP+(CH+GAP)*7+8;
  var lt=document.createElementNS(NS,'text');lt.setAttribute('x',LEFT);lt.setAttribute('y',ly+9);lt.setAttribute('fill','#475569');lt.setAttribute('font-size','9');lt.textContent='Less';svg.appendChild(lt);
  [0.05,0.2,0.4,0.65,0.85,1.0].forEach(function(v,i){var lr=document.createElementNS(NS,'rect');lr.setAttribute('x',LEFT+32+i*18);lr.setAttribute('y',ly);lr.setAttribute('width',14);lr.setAttribute('height',14);lr.setAttribute('rx','2');lr.setAttribute('fill',cellColor(v));svg.appendChild(lr);});
  var lt2=document.createElementNS(NS,'text');lt2.setAttribute('x',LEFT+32+6*18+4);lt2.setAttribute('y',ly+9);lt2.setAttribute('fill','#475569');lt2.setAttribute('font-size','9');lt2.textContent='More';svg.appendChild(lt2);
  container.appendChild(svg);
  container._tt=tooltip;
}

/* ──────────────────────────── §10  SHELL / ENTRY POINT ──────────────────── */
window.renderDarkWeb=function(){
  var container=document.getElementById('page-dark-web');if(!container)return;
  if(_s.graph.animFrame){cancelAnimationFrame(_s.graph.animFrame);_s.graph.animFrame=null;}
  /* cleanup old tooltips */
  document.querySelectorAll('.v2-heatmap-tooltip').forEach(function(tt){tt.remove();});
  container.className='p19-module';container.innerHTML='';
  var root=_el('div','v2-root');root.id='cdwie-root';container.appendChild(root);
  root.appendChild(_buildKPIBar());
  root.appendChild(_buildHeader());
  root.appendChild(_buildTabs());
  var panel=_el('div','v2-engine-panel');panel.id='cdwie-engine-panel';root.appendChild(panel);
  setTimeout(function(){_cdwieTab(_s.activeTab||'cognitive-search');},60);
  setTimeout(_animateKPIs,250);
  _startSimulation();
  setInterval(function(){_qsa('.v2-live-ts').forEach(function(el){el.textContent=_ago(_s.lastUpdated);});},5000);
  setInterval(function(){_s.kpis.queries+=_rand(1,4);var el=document.getElementById('kpi-queries');if(el)_flipNum(el,_s.kpis.queries);},45000);
};

function _buildKPIBar(){
  var kpis=[
    {val:_s.kpis.queries,label:'AI Queries',icon:'fa-brain',cls:'v2-kpi-cyan',id:'kpi-queries'},
    {val:_s.kpis.actors,label:'Actors in DB',icon:'fa-users',cls:'v2-kpi-purple',id:'kpi-actors'},
    {val:_s.kpis.nodes,label:'Graph Nodes',icon:'fa-project-diagram',cls:'v2-kpi-blue',id:'kpi-nodes'},
    {val:_s.kpis.threats,label:'Threats 7d',icon:'fa-exclamation-triangle',cls:'v2-kpi-orange',id:'kpi-threats'},
    {val:_s.kpis.credibility,label:'Credibility',icon:'fa-shield-alt',cls:'v2-kpi-green',id:'kpi-cred',suffix:'%'},
    {val:_s.kpis.briefed,label:'AI Briefed',icon:'fa-robot',cls:'v2-kpi-teal',id:'kpi-briefed'},
    {val:_s.kpis.reports,label:'Reports',icon:'fa-file-contract',cls:'v2-kpi-yellow',id:'kpi-reports'}
  ];
  var bar=_el('div','v2-kpi-bar');
  kpis.forEach(function(k){
    var item=_el('div','v2-kpi-item');
    item.innerHTML='<i class="fas '+k.icon+' v2-kpi-icon '+k.cls+'"></i><div class="v2-kpi-val '+k.cls+'" id="'+k.id+'">'+k.val+(k.suffix||'')+'</div><div class="v2-kpi-label">'+k.label+'</div>';
    bar.appendChild(item);
  });
  return bar;
}
function _animateKPIs(){
  [{id:'kpi-queries',val:_s.kpis.queries},{id:'kpi-actors',val:_s.kpis.actors},{id:'kpi-nodes',val:_s.kpis.nodes},{id:'kpi-threats',val:_s.kpis.threats},{id:'kpi-briefed',val:_s.kpis.briefed},{id:'kpi-reports',val:_s.kpis.reports}
  ].forEach(function(p,i){setTimeout(function(){var el=document.getElementById(p.id);if(el)_countUp(el,p.val,900);},i*80);});
}

var _slogans=['Eye Detects Everything. AI Protects Everything.','Dark Web Signals. Real-Time Intelligence.','Neural Correlation. Zero Analyst Input.','Live Threat Feed. Instant IOC Extraction.','Kill Chain Tracking. Autonomous Stage Detection.'];
var _sloganIdx=0;
function _buildHeader(){
  var h=_el('div','v2-header');
  h.innerHTML='<div class="v2-header-left"><div class="v2-header-icon"><i class="fas fa-spider"></i></div><div>'+
    '<div class="v2-header-title">COGNITIVE DARK WEB INTELLIGENCE ENGINE <span class="v2-version-badge">v2.0</span></div>'+
    '<div class="v2-header-sub" id="v2-slogan">'+_slogans[0]+'</div>'+
    '<div style="margin-top:5px;display:flex;align-items:center;gap:8px">'+
      '<span class="v2-status-badge"><span class="v2-status-dot"></span>ACTIVE MONITORING</span>'+
      '<span style="color:#475569;font-size:10px">Live \u00b7 <span class="v2-live-ts">just now</span></span>'+
    '</div></div></div>'+
    '<div class="v2-header-right">'+
    '<button class="v2-btn v2-btn-ghost" onclick="window._cdwiev2FeedToggle()"><i class="fas fa-satellite-dish"></i> Live Feed</button>'+
    '<button class="v2-btn v2-btn-ghost" onclick="window._cdwiev2AlertRules()"><i class="fas fa-bell"></i> Alerts</button>'+
    '<button class="v2-btn v2-btn-primary" onclick="window._cdwiev2Investigate()"><i class="fas fa-eye"></i> Investigate</button></div>';
  setInterval(function(){_sloganIdx=(_sloganIdx+1)%_slogans.length;var el=document.getElementById('v2-slogan');if(el){el.style.opacity='0';setTimeout(function(){el.textContent=_slogans[_sloganIdx];el.style.opacity='1';},300);}},6000);
  return h;
}

var _TABS2=[
  {id:'cognitive-search',label:'Cognitive Search',icon:'fa-brain',color:'#22d3ee',badge:''},
  {id:'actor-dna',label:'Threat Actor DNA',icon:'fa-dna',color:'#a855f7',badge:Object.keys(DW2_ACTORS).length},
  {id:'knowledge-graph',label:'Adversary Graph',icon:'fa-project-diagram',color:'#3b82f6',badge:'40'},
  {id:'neural-correlator',label:'Neural Correlator',icon:'fa-bezier-curve',color:'#ec4899',badge:'NEW'},
  {id:'kill-chain',label:'Kill Chain Tracker',icon:'fa-crosshairs',color:'#f97316',badge:DW2_CAMPAIGNS.length},
  {id:'dark-feed',label:'Dark Feed Live',icon:'fa-satellite-dish',color:'#22c55e',badge:'LIVE'},
  {id:'predictive',label:'Predictive Intel',icon:'fa-chart-line',color:'#f59e0b',badge:''},
  {id:'deception',label:'Deception Detect',icon:'fa-shield-virus',color:'#ef4444',badge:''},
  {id:'reporting',label:'Exec Reports',icon:'fa-file-contract',color:'#14b8a6',badge:''}
];
function _buildTabs(){
  var nav=_el('div','v2-tabs');
  _TABS2.forEach(function(t){
    var tab=_el('div','v2-tab');tab.dataset.tab=t.id;tab.style.setProperty('--tab-color',t.color);
    tab.innerHTML='<i class="fas '+t.icon+'"></i> '+t.label+(t.badge?'<span class="v2-tab-badge">'+t.badge+'</span>':'');
    tab.addEventListener('click',function(){_cdwieTab(t.id);});
    nav.appendChild(tab);
  });
  return nav;
}

function _cdwieTab(tabId){
  _s.activeTab=tabId;
  _qsa('.v2-tab').forEach(function(t){t.classList.toggle('active',t.dataset.tab===tabId);});
  /* stop graph loop if leaving graph tab */
  if(tabId!=='knowledge-graph'&&_s.graph.animFrame){cancelAnimationFrame(_s.graph.animFrame);_s.graph.animFrame=null;}
  /* cleanup tooltips */
  document.querySelectorAll('.v2-heatmap-tooltip').forEach(function(tt){tt.remove();});
  var panel=document.getElementById('cdwie-engine-panel');if(!panel)return;
  switch(tabId){
    case'cognitive-search':panel.innerHTML=_buildCognitiveSearch();break;
    case'actor-dna':panel.innerHTML=_buildActorDNA();break;
    case'knowledge-graph':panel.innerHTML=_buildKnowledgeGraph();break;
    case'neural-correlator':panel.innerHTML=_buildNeuralCorrelator();break;
    case'kill-chain':panel.innerHTML=_buildKillChain();break;
    case'dark-feed':panel.innerHTML=_buildDarkFeed();break;
    case'predictive':panel.innerHTML=_buildPredictive();break;
    case'deception':panel.innerHTML=_buildDeception();break;
    case'reporting':panel.innerHTML=_buildReporting();break;
    default:panel.innerHTML='<div class="v2-empty">Engine not found: '+_e(tabId)+'</div>';
  }
  var ed=_qs('.v2-engine',panel);if(ed)ed.classList.add('active');
  setTimeout(function(){
    if(tabId==='actor-dna'){_renderActorProfile(_s.actor.selected);_startHeatmapPolling(_s.actor.selected);}
    else if(tabId==='knowledge-graph')_initGraph();
    else if(tabId==='neural-correlator')_initNeuralGraph();
    else if(tabId==='kill-chain')_renderKillChain(_s.killchain.selectedCampaign);
    else if(tabId==='dark-feed')_initDarkFeed();
    else if(tabId==='predictive')_initPredictiveCharts();
  },80);
}
window._cdwieTab=_cdwieTab;

/* ──────────────────────── §11  COGNITIVE SEARCH ENGINE ──────────────────── */
var _SEARCH_QUERIES=['APT29 SUNBURST indicators 2025','LockBit 4.0 healthcare victims Q2 2025','Lazarus crypto exchange TTPs','zero-day exploits sold dark web 2025','FIN7 GRIFFON v4 YARA rules','credential dumps government sector 2025','IRON RANSOM campaign IOCs','DarkComet RAT dark web marketplace','nation-state APT infrastructure overlap','ransomware negotiation tactics 2025'];
var _SEARCH_RESULTS=[
  {id:'r1',type:'actor',title:'APT29 \u2014 Midnight Blizzard',relevance:98,iocs:['svr-proxy[.]net','40.127.235.1','HAMMERTOSS_v4.dll'],summary:'SVR-linked group. Active WINTER STORM campaign targeting EU government ministries. HAMMERTOSS v4 C2 infrastructure confirmed on AWS.',tags:['Russia','SVR','CRITICAL']},
  {id:'r2',type:'campaign',title:'IRON RANSOM \u2014 LockBit 4.0 Active Campaign',relevance:95,iocs:['lockbit4[.]onion','195.54.162.88','StealBit_v3.exe'],summary:'Active lateral movement confirmed. Hospital network compromised. 36h window to exfiltration/encryption. ISOLATE immediately.',tags:['Ransomware','CRITICAL','Active']},
  {id:'r3',type:'malware',title:'HAMMERTOSS v4 \u2014 C2 Beacon',relevance:91,iocs:['HAMMERTOSS_v4.dll (MD5: a3b7c2...)','*.azurewebsites.net:443','Twitter GitHub steganography'],summary:'Updated HAMMERTOSS using Twitter + GitHub for covert C2. Evades DPI. Deployed by APT29 in WINTER STORM.',tags:['APT29','Steganography','C2']},
  {id:'r4',type:'ioc',title:'LockBit 4.0 Infrastructure IOCs',relevance:89,iocs:['195.54.162.88','195.54.162.91','lockbit4[.]onion','lockbitapt[.]onion'],summary:'LockBit 4.0 C2 and leak-site infrastructure. Bulletproof hosted RU. StealBit exfil confirmed on .88.',tags:['LockBit','Infrastructure','IOC']},
  {id:'r5',type:'darkweb',title:'Dark Web Forum: LockBit 4.0 Affiliate Recruitment',relevance:85,iocs:['xss.is/t/12847','exploit.in/topic/98231'],summary:'Active affiliate recruitment. 70/30 split advertised. English and Russian speakers. Access broker partnerships offered.',tags:['Forum','Recruitment','RaaS']},
  {id:'r6',type:'actor',title:'FIN7 \u2014 GRIFFON v4 Update',relevance:83,iocs:['GRIFFON.js.b64','payment-process[.]net','BOOSTWRITE_loader.dll'],summary:'GRIFFON v4 JavaScript implant with new AMSI bypass via COM hijack. Deployed in SILENT RANSOM campaign.',tags:['FIN7','JavaScript','Financial']},
  {id:'r7',type:'malware',title:'Lumma Stealer v5 \u2014 New Variant',relevance:79,iocs:['lumma5_loader.exe (SHA256: f8d4...)','c2-lumma[.]xyz','*.top/gate.php'],summary:'Lumma v5 adds browser extension theft, crypto wallet drain, Discord token extraction. Sold $300/month on dark web.',tags:['Infostealer','Credentials','Malware']},
  {id:'r8',type:'campaign',title:'DRAGONFLY III \u2014 APT41 Active Recon',relevance:76,iocs:['ShadowPad_cfg.bin','update.microsoft.*.com'],summary:'APT41 initial access phase. CVE-2024-21887 exploitation on Ivanti appliances. Telecom sector targeted.',tags:['APT41','China','Espionage']}
];
function _buildCognitiveSearch(){
  var chips=_SEARCH_QUERIES.slice(0,6).map(function(q){return'<button class="v2-chip" onclick="window._cdwieSearch(\''+q.replace(/'/g,"\\'")+'\')">'+ q+'</button>';}).join('');
  return'<div class="v2-engine" id="v2-engine-search">'+
    '<div class="v2-search-hero">'+
      '<div class="v2-search-icon"><i class="fas fa-brain"></i></div>'+
      '<h2 class="v2-search-title">Cognitive Dark Web Search</h2>'+
      '<p class="v2-search-sub">AI-powered query across dark forums, paste sites, telegram channels & threat intel feeds</p>'+
      '<div class="v2-search-bar">'+
        '<i class="fas fa-search v2-search-ico"></i>'+
        '<input id="v2-search-input" class="v2-search-input" type="text" placeholder="Search threat actors, IOCs, campaigns, malware..." value="'+_e(_s.search.query)+'" onkeydown="if(event.key===\'Enter\')window._cdwieSearch()"/>'+
        '<button class="v2-btn v2-btn-primary" onclick="window._cdwieSearch()"><i class="fas fa-bolt"></i> Analyze</button>'+
      '</div>'+
      '<div class="v2-search-chips">'+chips+'</div>'+
    '</div>'+
    '<div class="v2-search-filters" id="v2-search-filters" style="display:none">'+
      ['all','actor','campaign','malware','ioc','darkweb'].map(function(f,i){return'<button class="v2-filter-btn'+(i===0?' active':'')+'" onclick="window._cdwieFilterSearch(this,\''+f+'\')">'+f.charAt(0).toUpperCase()+f.slice(1)+'</button>';}).join('')+
    '</div>'+
    '<div id="v2-search-results"></div>'+
  '</div>';
}
window._cdwieSearch=function(q){
  var input=document.getElementById('v2-search-input');
  var query=q||(input&&input.value)||'';
  if(!query)return;
  if(input)input.value=query;
  _s.search.query=query;_s.search.running=true;
  var resultsEl=document.getElementById('v2-search-results');
  var filtersEl=document.getElementById('v2-search-filters');
  if(!resultsEl)return;
  if(filtersEl)filtersEl.style.display='flex';
  resultsEl.innerHTML='<div class="v2-loading"><div class="v2-spinner"></div><div style="color:#94a3b8;font-size:14px">Querying dark web sources\u2026</div></div>';
  var steps=['Scanning dark forums (47 sources)\u2026','Cross-referencing MITRE ATT&CK\u2026','Correlating with actor database\u2026','Extracting IOCs\u2026','Ranking by relevance\u2026'];
  var si=0;
  var stepsEl=_el('div','v2-search-steps');
  resultsEl.appendChild(stepsEl);
  var st=setInterval(function(){
    if(si<steps.length){stepsEl.innerHTML+='<div class="v2-search-step"><i class="fas fa-check-circle" style="color:#22c55e"></i> '+steps[si]+'</div>';si++;}
    else{clearInterval(st);_showSearchResults(query);}
  },380);
};
function _showSearchResults(query){
  var resultsEl=document.getElementById('v2-search-results');if(!resultsEl)return;
  var filtered=_SEARCH_RESULTS.filter(function(r){
    return!query||r.title.toLowerCase().includes(query.toLowerCase())||r.summary.toLowerCase().includes(query.toLowerCase())||r.tags.some(function(t){return t.toLowerCase().includes(query.toLowerCase());});
  });
  if(!filtered.length)filtered=_SEARCH_RESULTS.slice(0,4);
  var typeIcons={actor:'fa-user-secret',campaign:'fa-crosshairs',malware:'fa-bug',ioc:'fa-fingerprint',darkweb:'fa-spider'};
  var typeColors={actor:'#ef4444',campaign:'#f97316',malware:'#a855f7',ioc:'#22d3ee',darkweb:'#ec4899'};
  var html='<div class="v2-results-header"><span style="color:#94a3b8;font-size:13px">'+filtered.length+' results for <strong style="color:#f1f5f9">\u201c'+_e(query)+'\u201d</strong></span><span class="v2-results-ai-badge"><i class="fas fa-brain"></i> AI-ranked</span></div>';
  html+=filtered.map(function(r,i){
    var color=typeColors[r.type]||'#6366f1';var icon=typeIcons[r.type]||'fa-circle';
    var iocs=r.iocs.map(function(ioc){return'<code class="v2-ioc-tag">'+_e(ioc)+'</code>';}).join('');
    var tags=r.tags.map(function(t){return'<span class="v2-badge v2-badge-blue">'+_e(t)+'</span>';}).join('');
    return'<div class="v2-result-card" style="animation-delay:'+(i*0.06)+'s;--rc:'+color+'" onclick="window._cdwieResultDetail(\''+r.id+'\')">'+
      '<div class="v2-result-type"><i class="fas '+icon+'" style="color:'+color+'"></i> '+r.type.toUpperCase()+'</div>'+
      '<div class="v2-result-relevance">'+r.relevance+'%</div>'+
      '<h3 class="v2-result-title">'+_e(r.title)+'</h3>'+
      '<p class="v2-result-summary">'+_e(r.summary)+'</p>'+
      (iocs?'<div class="v2-result-iocs">'+iocs+'</div>':'')+
      '<div class="v2-result-tags">'+tags+'</div>'+
    '</div>';
  }).join('');
  resultsEl.innerHTML=html;
}
window._cdwieFilterSearch=function(btn,type){
  _qsa('.v2-filter-btn').forEach(function(b){b.classList.remove('active');});btn.classList.add('active');
  _qsa('.v2-result-card').forEach(function(c){
    c.style.display=(type==='all'||c.querySelector('.v2-result-type').textContent.toLowerCase().includes(type))?'':'none';
  });
};
window._cdwieResultDetail=function(id){
  var r=_SEARCH_RESULTS.find(function(x){return x.id===id;});if(!r)return;
  _toast('Loaded: '+r.title,'info');
};

/* ──────────────────────────── §12  THREAT ACTOR DNA ─────────────────────── */
function _buildActorDNA(){
  var list=Object.values(DW2_ACTORS).map(function(a){
    var rc=a.threat==='CRITICAL'?'#ef4444':a.threat==='HIGH'?'#f97316':'#eab308';
    return'<div class="v2-actor-row'+(a.id===_s.actor.selected?' active':'')+'" onclick="window._cdwieSelectActor(\''+a.id+'\')" data-actor="'+a.id+'">'+
      '<div class="v2-actor-avatar" style="background:'+a.color+'22;color:'+a.color+'"><i class="fas '+(a.faIcon||'fa-user-secret')+'"></i></div>'+
      '<div class="v2-actor-info"><div class="v2-actor-name">'+a.flag+' '+_e(a.name)+'</div><div class="v2-actor-alias">'+_e(a.alias)+'</div></div>'+
      '<div style="color:'+rc+'"><i class="fas fa-circle" style="font-size:7px"></i></div>'+
    '</div>';
  }).join('');
  return'<div class="v2-engine" id="v2-engine-dna">'+
    '<div class="v2-actor-layout">'+
      '<div class="v2-actor-roster">'+
        '<div class="v2-roster-header"><span class="v2-roster-title"><i class="fas fa-users"></i> Threat Actors</span><span class="v2-badge v2-badge-critical">'+Object.keys(DW2_ACTORS).length+' tracked</span></div>'+
        '<div class="v2-actor-list">'+list+'</div>'+
      '</div>'+
      '<div class="v2-actor-detail" id="v2-actor-detail"><div id="v2-actor-profile"></div></div>'+
    '</div>'+
  '</div>';
}
window._cdwieSelectActor=function(id){
  _s.actor.selected=id;_s.actor.dnaTab='overview';
  _qsa('.v2-actor-row').forEach(function(r){r.classList.toggle('active',r.dataset.actor===id);});
  _renderActorProfile(id);_startHeatmapPolling(id);
};
function _renderActorProfile(id){
  var a=DW2_ACTORS[id];if(!a)return;
  var cont=document.getElementById('v2-actor-profile');if(!cont)return;
  var rc=a.threat==='CRITICAL'?'#ef4444':a.threat==='HIGH'?'#f97316':'#eab308';
  var tabs=['overview','behavior','ttps','infra','timeline'].map(function(t){
    return'<button class="v2-dna-tab'+(t===_s.actor.dnaTab?' active':'')+'" onclick="window._cdwieDNATab(\''+id+'\',\''+t+'\')"><i class="fas fa-'+
      {overview:'info-circle',behavior:'dna',ttps:'sitemap',infra:'server',timeline:'history'}[t]+'"></i> '+t.charAt(0).toUpperCase()+t.slice(1)+'</button>';
  }).join('');
  var attrBars=a.attributionSignals.map(function(sig){
    return'<div class="v2-attr-row"><span class="v2-attr-label">'+_e(sig.label)+'</span><div class="v2-attr-bar-wrap"><div class="v2-attr-bar" style="width:'+sig.score+'%;background:'+a.color+'"></div></div><span class="v2-attr-val">'+sig.score+'%</span><span class="v2-attr-weight">(w:'+sig.weight+'%)</span></div>';
  }).join('');
  var driftBadge=a.ttpDriftDetected?'<span class="v2-badge v2-badge-high" style="margin-left:8px"><i class="fas fa-exclamation-triangle"></i> TTP Drift Detected</span>':'';
  cont.innerHTML=
    '<div class="v2-actor-profile">'+
      '<div class="v2-actor-profile-header">'+
        '<div class="v2-actor-avatar-lg" style="background:'+a.color+'22;color:'+a.color+'"><i class="fas '+(a.faIcon||'fa-user-secret')+'"></i></div>'+
        '<div class="v2-actor-profile-meta">'+
          '<h2 class="v2-actor-profile-name">'+a.flag+' '+_e(a.name)+driftBadge+'</h2>'+
          '<div class="v2-actor-profile-aliases">'+a.aliases.join(' \u00b7 ')+'</div>'+
          '<div class="v2-actor-profile-badges">'+
            '<span class="v2-badge" style="background:'+rc+'22;color:'+rc+'">'+a.threat+' THREAT</span>'+
            '<span class="v2-badge v2-badge-blue">Confidence: '+a.confidence+'%</span>'+
            '<span class="v2-badge v2-badge-green">'+_e(a.active)+'</span>'+
          '</div>'+
        '</div>'+
        '<div class="v2-actor-stats">'+
          '<div class="v2-stat-chip"><div class="v2-stat-val">'+a.ttps.length+'</div><div class="v2-stat-lbl">TTPs</div></div>'+
          '<div class="v2-stat-chip"><div class="v2-stat-val">'+a.tools.length+'</div><div class="v2-stat-lbl">Tools</div></div>'+
          '<div class="v2-stat-chip"><div class="v2-stat-val">'+a.sectors.length+'</div><div class="v2-stat-lbl">Sectors</div></div>'+
          '<div class="v2-stat-chip"><div class="v2-stat-val">'+a.fingerprintScore+'</div><div class="v2-stat-lbl">Fingerprint</div></div>'+
        '</div>'+
      '</div>'+
      '<div class="v2-attr-section">'+attrBars+'</div>'+
      '<div class="v2-dna-tabs">'+tabs+'</div>'+
      '<div class="v2-dna-content" id="v2-dna-content">'+_renderDNATab(a,_s.actor.dnaTab)+'</div>'+
    '</div>';
  if(_s.actor.dnaTab==='behavior')setTimeout(function(){_initRadarChart(a);},100);
}
window._cdwieDNATab=function(actorId,tab){
  _s.actor.dnaTab=tab;
  _qsa('.v2-dna-tab').forEach(function(b){b.classList.toggle('active',b.textContent.toLowerCase().includes(tab.replace('-',' ').split(' ')[0]));});
  var a=DW2_ACTORS[actorId];if(!a)return;
  var tc=document.getElementById('v2-dna-content');if(tc){tc.innerHTML=_renderDNATab(a,tab);if(tab==='behavior')setTimeout(function(){_initRadarChart(a);},100);}
};
function _renderDNATab(a,tab){
  if(tab==='overview'){
    var sectors=a.sectors.map(function(s){return'<span class="v2-badge v2-badge-blue">'+_e(s)+'</span>';}).join('');
    return'<div class="v2-dna-overview">'+
      '<p class="v2-actor-desc">'+_e(a.desc)+'</p>'+
      '<div class="v2-ov-grid">'+
        '<div class="v2-ov-item"><span class="v2-ov-lbl"><i class="fas fa-globe"></i> Origin</span><span class="v2-ov-val">'+a.flag+' '+_e(a.origin)+'</span></div>'+
        '<div class="v2-ov-item"><span class="v2-ov-lbl"><i class="fas fa-building"></i> Sponsor</span><span class="v2-ov-val">'+_e(a.sponsor)+'</span></div>'+
        '<div class="v2-ov-item"><span class="v2-ov-lbl"><i class="fas fa-clock"></i> Active Since</span><span class="v2-ov-val">'+_e(a.active)+'</span></div>'+
        '<div class="v2-ov-item"><span class="v2-ov-lbl"><i class="fas fa-moon"></i> Op Hours</span><span class="v2-ov-val">'+_e(a.opHours)+'</span></div>'+
        '<div class="v2-ov-item"><span class="v2-ov-lbl"><i class="fas fa-pen-nib"></i> Writing Style</span><span class="v2-ov-val">'+_e(a.writingStyle)+'</span></div>'+
      '</div>'+
      '<div class="v2-ov-sectors"><span class="v2-ov-lbl">Target Sectors</span><div>'+sectors+'</div></div>'+
    '</div>';
  }
  if(tab==='behavior'){
    var b=a.behavior;var rows=Object.keys(b).map(function(k){var v=b[k];return'<div class="v2-beh-row"><span class="v2-beh-lbl">'+k.replace(/_/g,' ').replace(/\b\w/g,function(c){return c.toUpperCase();})+'</span><div class="v2-beh-bar-wrap"><div class="v2-beh-bar" style="width:'+v+'%;background:'+a.color+'"></div></div><span class="v2-beh-val">'+v+'</span></div>';}).join('');
    return'<div class="v2-dna-behavior"><div class="v2-radar-wrap"><canvas id="v2-radar-chart" width="280" height="280"></canvas></div><div class="v2-beh-bars">'+rows+'</div></div>';
  }
  if(tab==='ttps'){
    var tMap={'T1566':'Phishing','T1059':'Command & Scripting Interpreter','T1547':'Boot or Logon Autostart','T1078':'Valid Accounts','T1070':'Indicator Removal','T1021':'Remote Services','T1560':'Archive Collected Data','T1041':'Exfiltration over C2','T1190':'Exploit Public-Facing App','T1055':'Process Injection','T1003':'OS Credential Dumping','T1071':'Application Layer Protocol','T1036':'Masquerading','T1053':'Scheduled Task','T1027':'Obfuscated Files','T1486':'Data Encrypted for Impact','T1490':'Inhibit System Recovery','T1489':'Service Stop','T1505':'Server Software Component','T1195':'Supply Chain Compromise','T1552':'Unsecured Credentials','T1566.001':'Spearphishing Attachment','T1059.001':'PowerShell','T1059.003':'Windows Command Shell','T1059.007':'JavaScript','T1021.002':'SMB/Windows Admin Shares','T1053.005':'Scheduled Task','T1055.001':'DLL Injection','T1071.001':'Web Protocols'};
    var phases=['Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion','Lateral Movement','Collection','Exfiltration','Impact'];
    var rows=a.ttps.map(function(ttp,i){
      var base=ttp.split('.')[0];var name=tMap[ttp]||tMap[base]||ttp;var phase=phases[i%phases.length];
      return'<div class="v2-mitre-row"><span class="v2-mitre-id">'+_e(ttp)+'</span><span class="v2-mitre-name">'+_e(name)+'</span><span class="v2-badge v2-badge-purple">'+_e(phase)+'</span></div>';
    }).join('');
    return'<div class="v2-dna-ttps"><div class="v2-mitre-grid">'+rows+'</div></div>';
  }
  if(tab==='infra'){
    var inf=a.infra;
    var asns=(inf.asns||[]).map(function(x){return'<span class="v2-badge v2-badge-blue">'+_e(x)+'</span>';}).join('')||'<span class="v2-dim">None on record</span>';
    var hosts=(inf.hostingProviders||[]).map(function(x){return'<span class="v2-badge v2-badge-orange">'+_e(x)+'</span>';}).join('')||'<span class="v2-dim">None on record</span>';
    var c2s=(inf.c2Domains||[]).map(function(x){return'<code class="v2-ioc-tag">'+_e(x)+'</code>';}).join('')||'<span class="v2-dim">None on record</span>';
    return'<div class="v2-dna-infra">'+
      '<div class="v2-infra-sect"><h4><i class="fas fa-network-wired"></i> ASNs</h4><div>'+asns+'</div></div>'+
      '<div class="v2-infra-sect"><h4><i class="fas fa-server"></i> Hosting Providers</h4><div>'+hosts+'</div></div>'+
      '<div class="v2-infra-sect"><h4><i class="fas fa-link"></i> Known C2 Domains</h4><div>'+c2s+'</div></div>'+
      '<div class="v2-infra-sect"><h4><i class="fas fa-th"></i> Activity Heatmap (UTC)</h4><div id="cdwie-heatmap-'+a.id+'"></div></div>'+
    '</div>';
  }
  if(tab==='timeline'){
    var tl=(a.timeline||[]).map(function(ev,i){
      return'<div class="v2-tl-item"><div class="v2-tl-dot" style="background:'+a.color+'"></div><div class="v2-tl-body"><div class="v2-tl-date">'+_e(ev.date)+'</div><div class="v2-tl-event">'+_e(ev.event)+'</div></div></div>';
    }).join('');
    return'<div class="v2-dna-timeline"><div class="v2-tl-line" style="border-color:'+a.color+'44">'+tl+'</div></div>';
  }
  return'';
}
function _initRadarChart(a){
  var canvas=document.getElementById('v2-radar-chart');if(!canvas||typeof Chart==='undefined')return;
  if(canvas._ci)canvas._ci.destroy();
  var b=a.behavior;var labels=Object.keys(b).map(function(k){return k.replace(/_/g,' ').replace(/\b\w/g,function(c){return c.toUpperCase();});});
  canvas._ci=new Chart(canvas,{type:'radar',data:{labels:labels,datasets:[{label:a.name,data:Object.values(b),backgroundColor:a.color+'33',borderColor:a.color,borderWidth:2,pointBackgroundColor:a.color,pointRadius:3}]},options:{responsive:false,scales:{r:{min:0,max:100,ticks:{display:false},grid:{color:'rgba(255,255,255,0.08)'},angleLines:{color:'rgba(255,255,255,0.08)'},pointLabels:{color:'#94a3b8',font:{size:9}}}},plugins:{legend:{display:false}},animation:{duration:700}}});
}

/* ──────────────────────────── §13  KNOWLEDGE GRAPH ──────────────────────── */
var _GRAPH_DATA=(function(){
  var actors=Object.values(DW2_ACTORS);
  var nodes=[];var edges=[];
  /* Actor nodes */
  actors.forEach(function(a,i){
    var angle=(i/actors.length)*Math.PI*2;var r=200;
    nodes.push({id:a.id,label:a.name,type:'actor',color:a.color,x:400+r*Math.cos(angle),y:300+r*Math.sin(angle),vx:0,vy:0,radius:18,data:a});
  });
  /* Tool nodes */
  var toolSet={};
  actors.forEach(function(a){a.tools.slice(0,2).forEach(function(t){if(!toolSet[t]){toolSet[t]={id:'t_'+t,label:t,type:'malware',color:'#f97316',x:_rand(100,700),y:_rand(100,500),vx:0,vy:0,radius:11,actors:[]};nodes.push(toolSet[t]);}toolSet[t].actors.push(a.id);});});
  Object.values(toolSet).forEach(function(t){t.actors.forEach(function(aid){edges.push({source:aid,target:t.id,type:'tool',width:1.5,color:'#f9731644'});});});
  /* Correlation edges from DW2_CORRELATIONS */
  DW2_CORRELATIONS.forEach(function(c){edges.push({source:c.source,target:c.target,type:c.type,width:Math.round(c.score/25)+1,color:c.score>80?'#ef444488':c.score>60?'#f9731666':'#6366f155',score:c.score,label:c.type});});
  return{nodes:nodes,edges:edges};
})();

function _buildKnowledgeGraph(){
  return'<div class="v2-engine" id="v2-engine-graph">'+
    '<div class="v2-graph-toolbar">'+
      '<span class="v2-graph-title"><i class="fas fa-project-diagram" style="color:#3b82f6"></i> Adversary Intelligence Graph</span>'+
      '<div style="flex:1"></div>'+
      '<button class="v2-graph-btn" onclick="window._cdwieGraphZoomIn()" title="Zoom In"><i class="fas fa-search-plus"></i></button>'+
      '<button class="v2-graph-btn" onclick="window._cdwieGraphZoomOut()" title="Zoom Out"><i class="fas fa-search-minus"></i></button>'+
      '<button class="v2-graph-btn" onclick="window._cdwieGraphReset()" title="Reset"><i class="fas fa-compress-arrows-alt"></i></button>'+
      '<button class="v2-graph-btn" id="v2-graph-live-btn" onclick="window._cdwieGraphToggleLive()"><i class="fas fa-play"></i> Physics</button>'+
      '<select class="v2-graph-select" onchange="window._cdwieGraphFilter(this.value)">'+
        '<option value="all">All nodes</option><option value="actor">Actors only</option>'+
        '<option value="malware">Malware only</option><option value="tooling">Tooling edges</option><option value="infra">Infra edges</option>'+
      '</select>'+
      '<div class="v2-graph-legend">'+
        '<span><span class="v2-graph-dot" style="background:#ef4444"></span>Actor</span>'+
        '<span><span class="v2-graph-dot" style="background:#f97316"></span>Malware</span>'+
        '<span><span class="v2-graph-dot" style="background:#3b82f6"></span>Infra</span>'+
      '</div>'+
    '</div>'+
    '<canvas id="v2-graph-canvas" style="width:100%;height:480px;background:#050810;cursor:grab"></canvas>'+
    '<div id="v2-graph-tooltip" class="v2-graph-tooltip" style="display:none"></div>'+
  '</div>';
}
function _initGraph(){
  var canvas=document.getElementById('v2-graph-canvas');if(!canvas)return;
  if(_s.graph.animFrame){cancelAnimationFrame(_s.graph.animFrame);_s.graph.animFrame=null;}
  canvas.width=canvas.offsetWidth||900;canvas.height=480;
  /* Deep-copy nodes so physics doesn't mutate master data */
  _s.graph.nodes=_GRAPH_DATA.nodes.map(function(n){return Object.assign({},n,{x:n.x,y:n.y,vx:(Math.random()-.5)*.5,vy:(Math.random()-.5)*.5});});
  _s.graph.edges=_GRAPH_DATA.edges;
  _s.graph.initialized=true;
  _graphLoop(canvas);
  /* Mouse/touch interaction */
  var dragging=null,mx=0,my=0,panning=false,panStartX=0,panStartY=0;
  canvas.onmousedown=function(ev){
    var pos=_graphPos(ev,canvas);var node=_graphNodeAt(pos.x,pos.y);
    if(node){dragging=node;canvas.style.cursor='grabbing';}
    else{panning=true;panStartX=ev.clientX;panStartY=ev.clientY;canvas.style.cursor='move';}
  };
  canvas.onmousemove=function(ev){
    mx=ev.clientX;my=ev.clientY;
    if(dragging){var pos=_graphPos(ev,canvas);dragging.x=pos.x;dragging.y=pos.y;dragging.vx=0;dragging.vy=0;}
    else if(panning){_s.graph.offsetX+=(ev.clientX-panStartX);_s.graph.offsetY+=(ev.clientY-panStartY);panStartX=ev.clientX;panStartY=ev.clientY;}
    else{var pos2=_graphPos(ev,canvas);var n2=_graphNodeAt(pos2.x,pos2.y);var tt=document.getElementById('v2-graph-tooltip');if(tt){if(n2){tt.style.display='block';tt.style.left=(ev.clientX+12)+'px';tt.style.top=(ev.clientY-8)+'px';tt.innerHTML='<strong>'+_e(n2.label)+'</strong><br><span style="color:#94a3b8">'+_e(n2.type)+'</span>'+(n2.data?'<br><span style="color:#475569">'+_e(n2.data.threat||'')+'</span>':'');}else{tt.style.display='none';}}}
  };
  canvas.onmouseup=function(){dragging=null;panning=false;canvas.style.cursor='grab';};
  canvas.onmouseleave=function(){dragging=null;panning=false;};
  canvas.onwheel=function(ev){ev.preventDefault();_s.graph.scale=_clamp(_s.graph.scale*(ev.deltaY<0?1.1:0.9),0.15,5);};
}
function _graphPos(ev,canvas){var r=canvas.getBoundingClientRect();return{x:(ev.clientX-r.left-_s.graph.offsetX)/_s.graph.scale,y:(ev.clientY-r.top-_s.graph.offsetY)/_s.graph.scale};}
function _graphNodeAt(x,y){return _s.graph.nodes.find(function(n){var dx=n.x-x,dy=n.y-y;return Math.sqrt(dx*dx+dy*dy)<(n.radius+4);});}
var _graphLive=false;
function _graphLoop(canvas){
  var ctx=canvas.getContext('2d');if(!ctx)return;
  function frame(){
    _s.graph.animFrame=requestAnimationFrame(frame);
    /* Physics */
    if(_graphLive){
      var nodes=_s.graph.nodes;
      /* repulsion */
      for(var i=0;i<nodes.length;i++)for(var j=i+1;j<nodes.length;j++){var dx=nodes[i].x-nodes[j].x,dy=nodes[i].y-nodes[j].y,dist=Math.sqrt(dx*dx+dy*dy)||1,force=2800/(dist*dist);nodes[i].vx+=dx/dist*force*0.016;nodes[i].vy+=dy/dist*force*0.016;nodes[j].vx-=dx/dist*force*0.016;nodes[j].vy-=dy/dist*force*0.016;}
      /* spring edges */
      _s.graph.edges.forEach(function(e){var s=nodes.find(function(n){return n.id===e.source;}),t=nodes.find(function(n){return n.id===e.target;});if(!s||!t)return;var dx=t.x-s.x,dy=t.y-s.y,dist=Math.sqrt(dx*dx+dy*dy)||1,force=(dist-120)*0.012;s.vx+=dx/dist*force;s.vy+=dy/dist*force;t.vx-=dx/dist*force;t.vy-=dy/dist*force;});
      /* integrate + damp */
      nodes.forEach(function(n){n.vx*=0.88;n.vy*=0.88;n.x=_clamp(n.x+n.vx,20,canvas.width-20);n.y=_clamp(n.y+n.vy,20,canvas.height-20);});
    }
    /* Draw */
    ctx.clearRect(0,0,canvas.width,canvas.height);
    ctx.save();ctx.translate(_s.graph.offsetX,_s.graph.offsetY);ctx.scale(_s.graph.scale,_s.graph.scale);
    /* edges */
    _s.graph.edges.forEach(function(e){var s=_s.graph.nodes.find(function(n){return n.id===e.source;}),t=_s.graph.nodes.find(function(n){return n.id===e.target;});if(!s||!t)return;ctx.beginPath();ctx.moveTo(s.x,s.y);ctx.lineTo(t.x,t.y);ctx.strokeStyle=e.color||'#33415566';ctx.lineWidth=(e.width||1)/_s.graph.scale;ctx.stroke();});
    /* nodes */
    _s.graph.nodes.forEach(function(n){ctx.beginPath();ctx.arc(n.x,n.y,n.radius,0,Math.PI*2);ctx.fillStyle=n.color+'33';ctx.fill();ctx.strokeStyle=n.color;ctx.lineWidth=2/_s.graph.scale;ctx.stroke();ctx.fillStyle=n.color;ctx.font=(n.radius*0.7)+'px Inter,sans-serif';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(n.label.substring(0,8),n.x,n.y);});
    ctx.restore();
  }
  frame();
}
window._cdwieGraphZoomIn=function(){_s.graph.scale=_clamp(_s.graph.scale*1.2,0.15,5);};
window._cdwieGraphZoomOut=function(){_s.graph.scale=_clamp(_s.graph.scale*0.8,0.15,5);};
window._cdwieGraphReset=function(){_s.graph.scale=1;_s.graph.offsetX=0;_s.graph.offsetY=0;};
window._cdwieGraphToggleLive=function(){_graphLive=!_graphLive;var btn=document.getElementById('v2-graph-live-btn');if(btn)btn.innerHTML='<i class="fas fa-'+(+_graphLive?'pause':'play')+'"></i> Physics';};
window._cdwieGraphFilter=function(type){_toast('Filter: '+type,'info');};

/* ──────────────────────────── §14  NEURAL CORRELATOR ─────────────────────── */
function _buildNeuralCorrelator(){
  return'<div class="v2-engine" id="v2-engine-neural">'+
    '<div class="v2-nc-layout">'+
      '<div class="v2-nc-panel">'+
        '<div class="v2-nc-header"><i class="fas fa-bezier-curve" style="color:#ec4899"></i> AI Correlation Matrix</div>'+
        '<div class="v2-nc-subtitle">Neural similarity engine detects shared infrastructure, tooling, and behavioral patterns across actors</div>'+
        '<canvas id="v2-neural-canvas" style="width:100%;height:380px;background:#050810;border-radius:10px;cursor:pointer"></canvas>'+
      '</div>'+
      '<div class="v2-nc-detail-panel" id="v2-nc-detail">'+
        '<div class="v2-nc-placeholder"><i class="fas fa-bezier-curve" style="font-size:32px;color:#ec489940;margin-bottom:12px"></i><br>Select a correlation edge to view analysis</div>'+
      '</div>'+
    '</div>'+
    '<div class="v2-nc-edge-list">'+
      DW2_CORRELATIONS.map(function(c){
        var scoreColor=c.score>=80?'#ef4444':c.score>=60?'#f97316':c.score>=40?'#eab308':'#22c55e';
        var sa=DW2_ACTORS[c.source],ta=DW2_ACTORS[c.target];
        return'<div class="v2-nc-edge-card" onclick="window._cdwieSelectCorrelation(\''+c.id+'\')" data-cid="'+c.id+'">'+
          '<div class="v2-nc-edge-actors">'+
            '<span class="v2-nc-actor-chip" style="background:'+(sa?sa.color:'#6366f1')+'22;color:'+(sa?sa.color:'#6366f1')+'">'+_e(sa?sa.name:c.source)+'</span>'+
            '<span style="color:#475569;font-size:12px"><i class="fas fa-arrows-alt-h"></i></span>'+
            '<span class="v2-nc-actor-chip" style="background:'+(ta?ta.color:'#6366f1')+'22;color:'+(ta?ta.color:'#6366f1')+'">'+_e(ta?ta.name:c.target)+'</span>'+
          '</div>'+
          '<div class="v2-nc-edge-meta">'+
            '<span class="v2-badge v2-badge-purple">'+_e(c.type)+'</span>'+
            '<span class="v2-nc-score" style="color:'+scoreColor+'">'+c.score+'% correlation</span>'+
          '</div>'+
        '</div>';
      }).join('')+
    '</div>'+
  '</div>';
}
function _initNeuralGraph(){
  var canvas=document.getElementById('v2-neural-canvas');if(!canvas)return;
  canvas.width=canvas.offsetWidth||600;canvas.height=380;
  var ctx=canvas.getContext('2d');if(!ctx)return;
  var actors=Object.keys(DW2_ACTORS);var R=130;var cx=canvas.width/2,cy=canvas.height/2;
  var positions={};actors.forEach(function(id,i){var angle=(i/actors.length)*Math.PI*2-Math.PI/2;positions[id]={x:cx+R*Math.cos(angle),y:cy+R*Math.sin(angle),color:DW2_ACTORS[id].color};});
  ctx.clearRect(0,0,canvas.width,canvas.height);
  /* edges */
  DW2_CORRELATIONS.forEach(function(c){var s=positions[c.source],t=positions[c.target];if(!s||!t)return;ctx.beginPath();ctx.moveTo(s.x,s.y);ctx.lineTo(t.x,t.y);var alpha=Math.round((c.score/100)*200).toString(16).padStart(2,'0');ctx.strokeStyle='#ec4899'+alpha;ctx.lineWidth=Math.round(c.score/25)+1;ctx.stroke();var mx2=(s.x+t.x)/2,my2=(s.y+t.y)/2;ctx.fillStyle='#ec4899cc';ctx.font='10px Inter,sans-serif';ctx.textAlign='center';ctx.fillText(c.score+'%',mx2,my2);});
  /* nodes */
  actors.forEach(function(id){var p=positions[id];var a=DW2_ACTORS[id];if(!p||!a)return;ctx.beginPath();ctx.arc(p.x,p.y,18,0,Math.PI*2);ctx.fillStyle=a.color+'44';ctx.fill();ctx.strokeStyle=a.color;ctx.lineWidth=2;ctx.stroke();ctx.fillStyle=a.color;ctx.font='bold 10px Inter,sans-serif';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(a.name.substring(0,6),p.x,p.y);});
  /* click handler */
  canvas.onclick=function(ev){
    var r=canvas.getBoundingClientRect();var mx=ev.clientX-r.left,my=ev.clientY-r.top;
    var found=null;
    actors.forEach(function(id){var p=positions[id];if(!p)return;var dx=mx-p.x,dy=my-p.y;if(Math.sqrt(dx*dx+dy*dy)<20)found=id;});
    if(found){var relCorrs=DW2_CORRELATIONS.filter(function(c){return c.source===found||c.target===found;});_showNeuralDetail({actor:found,correlations:relCorrs});}
  };
}
window._cdwieSelectCorrelation=function(cid){
  var c=DW2_CORRELATIONS.find(function(x){return x.id===cid;});if(!c)return;
  _qsa('.v2-nc-edge-card').forEach(function(card){card.classList.toggle('active',card.dataset.cid===cid);});
  var sa=DW2_ACTORS[c.source],ta=DW2_ACTORS[c.target];
  var scoreColor=c.score>=80?'#ef4444':c.score>=60?'#f97316':c.score>=40?'#eab308':'#22c55e';
  var shared=c.shared.map(function(s){return'<div class="v2-nc-shared-item"><i class="fas fa-check" style="color:#22c55e"></i> '+_e(s)+'</div>';}).join('');
  var ttps=c.ttps.map(function(t){return'<span class="v2-badge v2-badge-purple">'+_e(t)+'</span>';}).join('');
  var det=document.getElementById('v2-nc-detail');if(!det)return;
  det.innerHTML='<div class="v2-nc-detail-inner">'+
    '<div class="v2-nc-detail-title">Correlation Analysis</div>'+
    '<div class="v2-nc-actors-row">'+
      '<div class="v2-nc-actor-block" style="border-color:'+(sa?sa.color:'#6366f1')+'">'+
        '<i class="fas '+(sa?sa.faIcon||'fa-user-secret':'fa-user-secret')+'" style="color:'+(sa?sa.color:'#6366f1')+';font-size:22px"></i>'+
        '<div>'+_e(sa?sa.name:c.source)+'</div>'+
      '</div>'+
      '<div class="v2-nc-score-display" style="color:'+scoreColor+'">'+c.score+'%<div style="font-size:11px;color:#475569">'+_e(c.type)+' overlap</div></div>'+
      '<div class="v2-nc-actor-block" style="border-color:'+(ta?ta.color:'#6366f1')+'">'+
        '<i class="fas '+(ta?ta.faIcon||'fa-user-secret':'fa-user-secret')+'" style="color:'+(ta?ta.color:'#6366f1')+';font-size:22px"></i>'+
        '<div>'+_e(ta?ta.name:c.target)+'</div>'+
      '</div>'+
    '</div>'+
    '<div class="v2-nc-section"><h4>Shared Indicators</h4>'+shared+'</div>'+
    '<div class="v2-nc-section"><h4>Overlapping TTPs</h4><div>'+ttps+'</div></div>'+
    '<div class="v2-nc-section"><h4>AI Assessment</h4><p class="v2-nc-assess">'+
      (c.score>=80?'STRONG evidence of operational overlap. Likely shared tooling or infrastructure. Consider collaborative attribution tracking.':c.score>=60?'MODERATE correlation detected. Shared access broker suspected. Monitor for coordinated campaign patterns.':'WEAK correlation. Circumstantial overlap only. Continue observing for confirming signals.')+
    '</p></div>'+
  '</div>';
};
function _showNeuralDetail(d){
  var a=DW2_ACTORS[d.actor];if(!a)return;
  var det=document.getElementById('v2-nc-detail');if(!det)return;
  det.innerHTML='<div class="v2-nc-detail-inner"><div class="v2-nc-detail-title">'+a.flag+' '+_e(a.name)+' \u2014 Correlations</div>'+
    d.correlations.map(function(c){
      var other=c.source===d.actor?DW2_ACTORS[c.target]:DW2_ACTORS[c.source];
      var sc=c.score>=80?'#ef4444':c.score>=60?'#f97316':'#eab308';
      return'<div class="v2-nc-edge-card active" onclick="window._cdwieSelectCorrelation(\''+c.id+'\')" data-cid="'+c.id+'">'+
        '<div class="v2-nc-edge-actors"><span class="v2-nc-actor-chip" style="color:'+(other?other.color:'#6366f1')+';background:'+(other?other.color:'#6366f1')+'22">'+_e(other?other.name:c.target)+'</span></div>'+
        '<div class="v2-nc-edge-meta"><span class="v2-badge v2-badge-purple">'+_e(c.type)+'</span><span class="v2-nc-score" style="color:'+sc+'">'+c.score+'%</span></div>'+
      '</div>';
    }).join('')+
  '</div>';
}

/* ──────────────────────────── §15  KILL CHAIN TRACKER ───────────────────── */
function _buildKillChain(){
  var navItems=DW2_CAMPAIGNS.map(function(c){
    var conf=c.confidence==='CRITICAL'?'#ef4444':c.confidence==='HIGH'?'#f97316':'#eab308';
    return'<div class="v2-kc-nav-item'+(c.id===_s.killchain.selectedCampaign?' active':'')+'" onclick="window._cdwieSelectCampaign(\''+c.id+'\')" data-cid="'+c.id+'">'+
      '<div class="v2-kc-nav-name">'+_e(c.name)+'</div>'+
      '<div class="v2-kc-nav-meta"><span style="color:#94a3b8;font-size:11px">'+_e(c.group)+'</span><span class="v2-badge" style="background:'+conf+'22;color:'+conf+'">'+c.prob+'%</span></div>'+
    '</div>';
  }).join('');
  return'<div class="v2-engine" id="v2-engine-killchain">'+
    '<div class="v2-kc-layout">'+
      '<div class="v2-kc-nav"><div class="v2-kc-nav-title"><i class="fas fa-crosshairs"></i> Active Campaigns</div>'+navItems+'</div>'+
      '<div class="v2-kc-main" id="v2-kc-main"></div>'+
    '</div>'+
  '</div>';
}
function _renderKillChain(campaignId){
  _s.killchain.selectedCampaign=campaignId;
  var c=DW2_CAMPAIGNS.find(function(x){return x.id===campaignId;});if(!c)return;
  var main=document.getElementById('v2-kc-main');if(!main)return;
  var conf=c.confidence==='CRITICAL'?'#ef4444':c.confidence==='HIGH'?'#f97316':c.confidence==='MEDIUM'?'#eab308':'#22c55e';
  var stagesHtml=c.stages.map(function(s){
    var isCurrent=s.id===c.currentStage;var isDone=s.id<c.currentStage;var isFuture=s.id>c.currentStage;
    var phaseIcons={recon:'fa-binoculars',initial:'fa-door-open',exec:'fa-terminal',persist:'fa-anchor',lateral:'fa-route',exfil:'fa-cloud-upload-alt'};
    var stateClass=isCurrent?'v2-stage-current':isDone?'v2-stage-done':s.confirmed?'v2-stage-confirmed':'v2-stage-future';
    var ttps=s.ttps.map(function(t){return'<span class="v2-badge v2-badge-purple">'+_e(t)+'</span>';}).join('');
    return'<div class="v2-stage '+stateClass+'">'+
      '<div class="v2-stage-icon"><i class="fas '+(phaseIcons[s.phase]||'fa-circle')+'"></i></div>'+
      '<div class="v2-stage-body">'+
        '<div class="v2-stage-name">'+_e(s.name)+'</div>'+
        '<div class="v2-stage-ttps">'+ttps+'</div>'+
        (isCurrent?'<div class="v2-stage-eta-badge v2-stage-eta-current"><i class="fas fa-circle-notch fa-spin"></i> IN PROGRESS</div>':'')+
        (isFuture&&s.prob?'<div class="v2-stage-eta-badge">ETA '+_e(s.eta)+' \u00b7 '+s.prob+'% probability</div>':'')+
        (isDone?'<div class="v2-stage-eta-badge v2-stage-eta-done"><i class="fas fa-check"></i> '+_e(s.eta)+'</div>':'')+
      '</div>'+
    '</div>';
  }).join('<div class="v2-stage-arrow"><i class="fas fa-chevron-right"></i></div>');
  var defenses=c.defenses.map(function(d,i){return'<div class="v2-defense-item"><span class="v2-defense-num">'+(i+1)+'</span><span>'+_e(d)+'</span></div>';}).join('');
  main.innerHTML=
    '<div class="v2-kc-header">'+
      '<div class="v2-kc-campaign-name">'+_e(c.name)+'</div>'+
      '<div class="v2-kc-campaign-meta">'+
        '<span class="v2-badge" style="background:'+conf+'22;color:'+conf+'">'+_e(c.confidence)+' CONFIDENCE</span>'+
        '<span class="v2-badge v2-badge-blue">'+c.prob+'% probability</span>'+
        '<span class="v2-badge v2-badge-orange">ETA: '+_e(c.eta)+'</span>'+
      '</div>'+
      '<div class="v2-kc-group"><i class="fas fa-user-secret"></i> '+_e(c.group)+'</div>'+
    '</div>'+
    '<div class="v2-kc-chain">'+stagesHtml+'</div>'+
    '<div class="v2-kc-defenses">'+
      '<div class="v2-kc-def-title"><i class="fas fa-shield-alt"></i> Recommended Defenses</div>'+
      defenses+
    '</div>';
}
window._cdwieSelectCampaign=function(id){
  _qsa('.v2-kc-nav-item').forEach(function(el){el.classList.toggle('active',el.dataset.cid===id);});
  _renderKillChain(id);
};

/* ──────────────────────────── §16  DARK FEED LIVE ───────────────────────── */
var _dfHandler=null;
function _buildDarkFeed(){
  var actorOpts=(['all']).concat(Object.values(DW2_ACTORS).map(function(a){return a.name;})).map(function(n){return'<option value="'+_e(n)+'">'+_e(n==='all'?'All Actors':n)+'</option>';}).join('');
  var typeOpts=['all','ransomware','apt','credential','crypto','exploit','recruitment'].map(function(t){return'<option value="'+t+'">'+_e(t==='all'?'All Types':t.charAt(0).toUpperCase()+t.slice(1))+'</option>';}).join('');
  return'<div class="v2-engine" id="v2-engine-darkfeed">'+
    '<div class="v2-df-toolbar">'+
      '<div class="v2-df-status"><span class="v2-ws-dot connected"></span><span class="v2-df-status-text">Simulated Intel Stream \u2014 Live</span></div>'+
      '<div style="flex:1"></div>'+
      '<select class="v2-graph-select" id="v2-df-actor-filter" onchange="window._cdwieDFFilter()">'+actorOpts+'</select>'+
      '<select class="v2-graph-select" id="v2-df-type-filter" onchange="window._cdwieDFFilter()">'+typeOpts+'</select>'+
      '<button class="v2-btn v2-btn-ghost" id="v2-df-pause-btn" onclick="window._cdwieDFPause()"><i class="fas fa-pause"></i> Pause</button>'+
      '<button class="v2-btn v2-btn-ghost" onclick="window._cdwieDFClear()"><i class="fas fa-trash"></i> Clear</button>'+
    '</div>'+
    '<div id="v2-darkfeed-list" class="v2-df-list"></div>'+
  '</div>';
}
function _initDarkFeed(){
  /* Render existing entries */
  var feedEl=document.getElementById('v2-darkfeed-list');if(!feedEl)return;
  feedEl.innerHTML='';
  _s.darkfeed.entries.slice(0,30).forEach(function(e){_prependFeedEntry(feedEl,e,true);});
  /* Register handler */
  if(_dfHandler)return;
  _dfHandler=true;/* mark registered */
}
function _prependFeedEntry(feedEl,entry,append){
  if(!feedEl)return;
  var f=_s.darkfeed.filter;
  if(f.actor!=='all'&&entry.actor!==f.actor)return;
  if(f.type!=='all'&&entry.type!==f.type)return;
  if(entry.sev<f.sev)return;
  var sevColor=entry.sev>=90?'#ef4444':entry.sev>=70?'#f97316':entry.sev>=50?'#eab308':'#22c55e';
  var typeIcons={ransomware:'fa-lock',apt:'fa-user-secret',credential:'fa-key',crypto:'fa-coins',exploit:'fa-bug',recruitment:'fa-handshake'};
  var iocs=(entry.iocs&&entry.iocs.length)?entry.iocs.map(function(i){return'<code class="v2-ioc-tag">'+_e(i)+'</code>';}).join(''):'';
  var card=_el('div','v2-df-entry');
  card.style.animation='v2fadeIn .3s ease';
  card.innerHTML=
    '<div class="v2-df-entry-header">'+
      '<div class="v2-df-sev" style="background:'+sevColor+'22;color:'+sevColor+'">'+entry.sev+'</div>'+
      '<i class="fas '+(typeIcons[entry.type]||'fa-circle')+'" style="color:'+sevColor+'"></i>'+
      '<span class="v2-df-actor">'+_e(entry.actor)+'</span>'+
      (entry.campaign?'<span class="v2-badge v2-badge-orange">'+_e(entry.campaign)+'</span>':'')+
      '<span class="v2-badge v2-badge-blue">'+_e(entry.type)+'</span>'+
      '<span class="v2-df-source"><i class="fas fa-globe"></i> '+_e(entry.source)+'</span>'+
      '<span class="v2-df-time">'+_ago(entry.ts)+'</span>'+
    '</div>'+
    '<div class="v2-df-summary">'+_e(entry.summary)+'</div>'+
    (iocs?'<div class="v2-df-iocs">'+iocs+'</div>':'')+
    '<div class="v2-df-actions">'+
      '<button class="v2-btn v2-btn-ghost" style="font-size:11px;padding:3px 8px" onclick="window._cdwieDFClassify('+entry.id+')"><i class="fas fa-tag"></i> Classify</button>'+
      '<button class="v2-btn v2-btn-ghost" style="font-size:11px;padding:3px 8px" onclick="window._cdwieDFAddToCase('+entry.id+')"><i class="fas fa-folder-plus"></i> Add to Case</button>'+
    '</div>';
  if(append){feedEl.appendChild(card);}else{feedEl.insertBefore(card,feedEl.firstChild);if(feedEl.children.length>80)feedEl.removeChild(feedEl.lastChild);}
}
window._cdwieDFPause=function(){
  _s.darkfeed.paused=!_s.darkfeed.paused;
  var btn=document.getElementById('v2-df-pause-btn');
  if(btn)btn.innerHTML=_s.darkfeed.paused?'<i class="fas fa-play"></i> Resume':'<i class="fas fa-pause"></i> Pause';
};
window._cdwieDFClear=function(){_s.darkfeed.entries=[];var el=document.getElementById('v2-darkfeed-list');if(el)el.innerHTML='<div class="v2-empty">Feed cleared</div>';};
window._cdwieDFFilter=function(){
  var af=document.getElementById('v2-df-actor-filter'),tf=document.getElementById('v2-df-type-filter');
  _s.darkfeed.filter.actor=af?af.value:'all';
  _s.darkfeed.filter.type=tf?tf.value:'all';
  var feedEl=document.getElementById('v2-darkfeed-list');if(!feedEl)return;
  feedEl.innerHTML='';
  _s.darkfeed.entries.slice(0,50).forEach(function(e){_prependFeedEntry(feedEl,e,true);});
};
window._cdwieDFClassify=function(id){_toast('IOC classified','success');};
window._cdwieDFAddToCase=function(id){_toast('Entry added to active case','info');};

/* hook simulation into feed renderer */
(function(){
  var origSim=_startSimulation;
  _startSimulation=function(){
    origSim();
    /* also register watcher that calls prependFeedEntry when dark feed tab is active */
    setInterval(function(){
      if(_s.activeTab==='dark-feed'&&!_s.darkfeed.paused){
        var feedEl=document.getElementById('v2-darkfeed-list');
        if(feedEl&&_s.darkfeed.entries.length>0){
          /* just let the sim timer drive updates via its own _prependFeedEntry call */
        }
      }
    },1000);
  };
})();

/* ──────────────────────────── §17  PREDICTIVE INTEL ─────────────────────── */
function _buildPredictive(){
  var score=74;
  var geoRows=[ ['United States',95,'Ransomware + APT'],['Ukraine',88,'State Warfare'],['Taiwan',80,'State Espionage'],['Israel',79,'State Espionage'],['Germany',78,'Industrial Espionage'],['Saudi Arabia',74,'Energy Targeting'],['South Korea',71,'State Espionage'],['UK',72,'Credential Theft'],['Japan',68,'IP Theft'],['France',65,'Government Targeting'] ].map(function(g){
    var c=g[1]>=90?'#ef4444':g[1]>=75?'#f97316':g[1]>=60?'#eab308':'#22c55e';
    return'<div class="v2-geo-row"><span class="v2-geo-label">'+_e(g[0])+'</span><div class="v2-geo-bar-wrap"><div class="v2-geo-bar" style="width:'+g[1]+'%;background:'+c+'"></div></div><span class="v2-geo-score" style="color:'+c+'">'+g[1]+'</span><span class="v2-geo-type">'+_e(g[2])+'</span></div>';
  }).join('');
  var emergingItems=[
    {type:'Ransomware',name:'HellCat Ransomware',conf:88},
    {type:'Exploit',name:'VMware vCenter RCE',conf:95},
    {type:'Malware',name:'Lumma Stealer v5',conf:82},
    {type:'0-Day',name:'Chrome Sandbox Escape',conf:91},
    {type:'RaaS',name:'Fog Ransomware v2',conf:86},
    {type:'Botnet',name:'Mirai.X Corp',conf:74},
    {type:'Malware',name:'TrueBot v4 Resurgence',conf:77},
    {type:'Campaign',name:'IRON TWILIGHT (APT29)',conf:79}
  ].map(function(e){
    var c=e.conf>=90?'#ef4444':e.conf>=80?'#f97316':'#eab308';
    return'<div class="v2-emerging-item"><span class="v2-badge v2-badge-purple">'+_e(e.type)+'</span><span class="v2-emerging-name">'+_e(e.name)+'</span><span class="v2-emerging-conf" style="color:'+c+'">'+e.conf+'%</span></div>';
  }).join('');
  return'<div class="v2-engine" id="v2-engine-predictive">'+
    '<div class="v2-pred-grid">'+
      '<div class="v2-pred-card v2-pred-score-card">'+
        '<div class="v2-pred-score-title">Global Threat Score</div>'+
        '<div class="v2-pred-gauge-wrap"><canvas id="v2-gauge-chart" width="200" height="120"></canvas></div>'+
        '<div class="v2-pred-score-val" id="v2-pred-score-num">'+score+'</div>'+
        '<div class="v2-pred-score-sub">Elevated \u2014 Immediate attention required</div>'+
      '</div>'+
      '<div class="v2-pred-card">'+
        '<div class="v2-pred-card-title"><i class="fas fa-chart-line"></i> Threat Factor Breakdown</div>'+
        '<canvas id="v2-factor-chart" height="160"></canvas>'+
      '</div>'+
      '<div class="v2-pred-card">'+
        '<div class="v2-pred-card-title"><i class="fas fa-globe"></i> Geographic Threat Heat</div>'+
        '<div class="v2-geo-list">'+geoRows+'</div>'+
      '</div>'+
      '<div class="v2-pred-card v2-pred-emerging-card">'+
        '<div class="v2-pred-card-title"><i class="fas fa-radiation"></i> Emerging Threats <span class="v2-badge v2-badge-critical">8 detected</span></div>'+
        '<div class="v2-emerging-list">'+emergingItems+'</div>'+
      '</div>'+
    '</div>'+
  '</div>';
}
function _initPredictiveCharts(){
  /* Gauge */
  var gc=document.getElementById('v2-gauge-chart');
  if(gc&&typeof Chart!=='undefined'){
    if(gc._ci)gc._ci.destroy();
    gc._ci=new Chart(gc,{type:'doughnut',data:{datasets:[{data:[74,26],backgroundColor:['#f97316','#1e293b'],borderWidth:0,circumference:180,rotation:-90}]},options:{responsive:false,cutout:'72%',plugins:{legend:{display:false},tooltip:{enabled:false}}}});
  }
  /* Factor bars chart */
  var fc=document.getElementById('v2-factor-chart');
  if(fc&&typeof Chart!=='undefined'){
    if(fc._ci)fc._ci.destroy();
    fc._ci=new Chart(fc,{type:'bar',data:{labels:['Dark Web\nChatter','Ransomware\nCampaigns','Credential\nExposure','APT Recon\nSignals','Zero-Day\nAvail.'],datasets:[{data:[82,91,68,77,55],backgroundColor:['#ef4444cc','#f97316cc','#eab308cc','#a855f7cc','#3b82f6cc'],borderRadius:4}]},options:{responsive:true,plugins:{legend:{display:false}},scales:{x:{grid:{color:'#1e293b'},ticks:{color:'#475569',font:{size:9}}},y:{min:0,max:100,grid:{color:'#1e293b'},ticks:{color:'#475569'}}}}});
  }
}

/* ──────────────────────────── §18  DECEPTION DETECT ─────────────────────── */
var _DECEPTION_SAMPLES=[
  {label:'APT29 Spear-phish',text:'Dear Security Team,\n\nAs per our recent audit requirements, please verify your credentials at https://microsof1t-secure-portal.com/verify within 24 hours.\n\nIT Security Department\nMicrosoft Corporation'},
  {label:'LockBit 4.0 Ransom Note',text:'YOUR NETWORK HAS BEEN COMPROMISED\n\nAll your files have been encrypted with RSA-2048 and AES-256.\nTo recover your data, visit: lockbit4.onion\nYour decryption key expires in: 72:00:00\nRansom: 2.8 BTC'},
  {label:'Fake Recruiter (FIN7)',text:'Hi,\n\nWe are CombiSecurity LLC, a licensed penetration testing company. We found your profile and are interested in hiring for a senior security researcher position. Remote work, $120K+. \n\nPlease review and run our skills assessment: assessment.zip\n\nBest, HR Team'},
  {label:'APT41 Watering Hole',text:'<script>var a=new ActiveXObject("WScript.Shell");a.Run("powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMA...");</script>'},
  {label:'Lazarus Crypto Lure',text:'Exclusive airdrop opportunity! Claim 2.5 ETH from the MetaMask Security Fund. Connect your wallet at metamask-security-airdrop[.]io to verify eligibility before Feb 28.'}
];
var _deceptionState={analyzing:false,result:null,sampleIdx:0,content:''};
function _buildDeception(){
  var chips=_DECEPTION_SAMPLES.map(function(s,i){return'<button class="v2-chip" onclick="window._cdwieLoadSample('+i+')">'+_e(s.label)+'</button>';}).join('');
  return'<div class="v2-engine" id="v2-engine-deception">'+
    '<div class="v2-deception-layout">'+
      '<div class="v2-deception-input-panel">'+
        '<div class="v2-deception-title"><i class="fas fa-shield-virus" style="color:#ef4444"></i> AI Deception Detection</div>'+
        '<div class="v2-deception-subtitle">Paste any suspicious content \u2014 emails, messages, code, documents \u2014 for AI attribution and threat classification</div>'+
        '<div class="v2-deception-samples">'+chips+'</div>'+
        '<textarea id="v2-deception-input" class="v2-deception-textarea" placeholder="Paste suspicious content here..."></textarea>'+
        '<div class="v2-deception-actions">'+
          '<button class="v2-btn v2-btn-primary" onclick="window._cdwieAnalyzeDeception()"><i class="fas fa-brain"></i> Analyze Content</button>'+
          '<button class="v2-btn v2-btn-ghost" onclick="window._cdwieClearDeception()"><i class="fas fa-times"></i> Clear</button>'+
        '</div>'+
      '</div>'+
      '<div class="v2-deception-results-panel" id="v2-deception-results">'+
        '<div class="v2-deception-placeholder"><i class="fas fa-shield-virus" style="font-size:40px;color:#ef444420;margin-bottom:12px"></i><br>Analysis results will appear here</div>'+
      '</div>'+
    '</div>'+
  '</div>';
}
window._cdwieLoadSample=function(i){var s=_DECEPTION_SAMPLES[i];if(!s)return;var ta=document.getElementById('v2-deception-input');if(ta){ta.value=s.text;_deceptionState.content=s.text;}};
window._cdwieClearDeception=function(){var ta=document.getElementById('v2-deception-input');if(ta)ta.value='';_deceptionState.result=null;var rp=document.getElementById('v2-deception-results');if(rp)rp.innerHTML='<div class="v2-deception-placeholder"><i class="fas fa-shield-virus" style="font-size:40px;color:#ef444420;margin-bottom:12px"></i><br>Analysis results will appear here</div>';};
window._cdwieAnalyzeDeception=function(){
  var ta=document.getElementById('v2-deception-input');var content=ta?ta.value:'';if(!content.trim()){_toast('Please paste content to analyze','warning');return;}
  var rp=document.getElementById('v2-deception-results');if(!rp)return;
  rp.innerHTML='<div class="v2-loading"><div class="v2-spinner"></div><div style="color:#94a3b8">Analyzing content\u2026</div></div>';
  setTimeout(function(){
    var isPhish=content.toLowerCase().includes('verify')||content.toLowerCase().includes('credential')||content.toLowerCase().includes('click here');
    var isRansom=content.toLowerCase().includes('encrypted')||content.toLowerCase().includes('bitcoin')||content.toLowerCase().includes('decrypt');
    var isMalicious=content.includes('<script')||content.includes('powershell')||content.includes('ActiveXObject');
    var isCrypto=content.toLowerCase().includes('wallet')||content.toLowerCase().includes('eth')||content.toLowerCase().includes('airdrop');
    var isSocial=content.toLowerCase().includes('assessment.zip')||content.toLowerCase().includes('remote work')||content.toLowerCase().includes('recruiter');
    var threatType=isMalicious?'Malicious Code/Exploit':isRansom?'Ransomware Communication':isPhish?'Phishing / Social Engineering':isCrypto?'Cryptocurrency Scam / Lazarus-style':isSocial?'Social Engineering (FIN7-style)':'Suspicious Content';
    var actor=isMalicious?'APT41':isRansom?'LockBit 4.0':isSocial?'FIN7':isCrypto?'Lazarus Group':isPhish?'APT29':'Unknown';
    var confidence=_rand(78,97);
    var indicators=[
      isPhish?'Homograph domain detected (microsof1t vs microsoft)':null,
      isRansom?'Onion site reference \u2014 known ransomware infrastructure':null,
      isMalicious?'Obfuscated PowerShell base64 payload':null,
      isCrypto?'Wallet address pattern \u2014 matches Lazarus crypto drain campaigns':null,
      isSocial?'Zip attachment social engineering \u2014 matches FIN7 Combi Security lure':null,
      'Urgency manipulation detected',
      'Authority impersonation indicators',
    ].filter(Boolean).slice(0,4);
    var iocList=[
      isPhish?'microsof1t-secure-portal[.]com':null,
      isRansom?'lockbit4[.]onion':null,
      isCrypto?'metamask-security-airdrop[.]io':null,
    ].filter(Boolean);
    rp.innerHTML='<div class="v2-deception-result">'+
      '<div class="v2-dr-header">'+
        '<div class="v2-dr-verdict v2-badge-critical"><i class="fas fa-exclamation-triangle"></i> MALICIOUS</div>'+
        '<div class="v2-dr-confidence">'+confidence+'% confidence</div>'+
      '</div>'+
      '<div class="v2-dr-grid">'+
        '<div class="v2-dr-item"><span class="v2-dr-lbl">Threat Type</span><span class="v2-dr-val">'+_e(threatType)+'</span></div>'+
        '<div class="v2-dr-item"><span class="v2-dr-lbl">Likely Actor</span><span class="v2-dr-val" style="color:'+(DW2_ACTORS[actor.toLowerCase().replace(/[^a-z]/g,'').replace('fin','fin')]||{color:'#ef4444'}).color+'">'+_e(actor)+'</span></div>'+
        '<div class="v2-dr-item"><span class="v2-dr-lbl">Campaign Match</span><span class="v2-dr-val">'+_rand(60,95)+'% match to known TTPs</span></div>'+
        '<div class="v2-dr-item"><span class="v2-dr-lbl">MITRE Phase</span><span class="v2-badge v2-badge-purple">'+(isPhish?'Initial Access':isRansom?'Impact':isMalicious?'Execution':isCrypto?'Exfiltration':'Collection')+'</span></div>'+
      '</div>'+
      '<div class="v2-dr-section"><h4>Indicators Detected</h4>'+indicators.map(function(i){return'<div class="v2-dr-indicator"><i class="fas fa-exclamation-circle" style="color:#ef4444"></i> '+_e(i)+'</div>';}).join('')+'</div>'+
      (iocList.length?'<div class="v2-dr-section"><h4>Extracted IOCs</h4>'+iocList.map(function(ioc){return'<code class="v2-ioc-tag">'+_e(ioc)+'</code>';}).join('')+'</div>':'')+
      '<div class="v2-dr-actions"><button class="v2-btn v2-btn-primary" onclick="_toast(\'IOC submitted to threat feed\',\'success\')"><i class="fas fa-share-alt"></i> Submit IOC</button><button class="v2-btn v2-btn-ghost" onclick="_toast(\'Report generated\',\'info\')"><i class="fas fa-file-alt"></i> Generate Report</button></div>'+
    '</div>';
  },1800);
};

/* ──────────────────────────── §19  EXECUTIVE REPORTS ────────────────────── */
function _buildReporting(){
  var reportTypes=[
    {id:'executive',icon:'fa-chart-pie',label:'Executive Summary',desc:'C-suite risk overview'},
    {id:'technical',icon:'fa-code',label:'Technical Deep-Dive',desc:'Full IOC + TTP analysis'},
    {id:'actor',icon:'fa-user-secret',label:'Threat Actor Profile',desc:'Single actor dossier'},
    {id:'campaign',icon:'fa-crosshairs',label:'Campaign Analysis',desc:'Kill chain + attribution'},
    {id:'ioc',icon:'fa-fingerprint',label:'IOC Bulletin',desc:'Indicator digest'}
  ];
  var rtCards=reportTypes.map(function(rt){
    return'<label class="v2-rtype-card'+(rt.id===_s.report.type?' active':'')+'" onclick="window._cdwieSetReportType(\''+rt.id+'\')">'+
      '<i class="fas '+rt.icon+'" style="font-size:20px;color:#6366f1;margin-bottom:6px"></i>'+
      '<div class="v2-rtype-label">'+_e(rt.label)+'</div>'+
      '<div class="v2-rtype-desc">'+_e(rt.desc)+'</div>'+
    '</label>';
  }).join('');
  var sections=_s.report.sections;
  var sectionItems=Object.keys(sections).map(function(k){
    return'<label class="v2-section-item"><input type="checkbox" '+(sections[k]?'checked':'')+' onchange="window._cdwieToggleSection(\''+k+'\',this.checked)"> '+k.replace(/_/g,' ').replace(/\b\w/g,function(c){return c.toUpperCase();})+'</label>';
  }).join('');
  return'<div class="v2-engine" id="v2-engine-reporting">'+
    '<div class="v2-report-layout">'+
      '<div class="v2-report-builder">'+
        '<div class="v2-report-title"><i class="fas fa-file-contract" style="color:#14b8a6"></i> Report Builder</div>'+
        '<div class="v2-rtype-grid">'+rtCards+'</div>'+
        '<div class="v2-report-opts">'+
          '<div class="v2-report-opt-row">'+
            '<label class="v2-opt-lbl">Timeframe</label>'+
            '<select class="v2-graph-select" onchange="window._cdwieSetReportTF(this.value)">'+
              ['24h','7d','30d','90d'].map(function(tf){return'<option value="'+tf+'"'+(_s.report.timeframe===tf?' selected':'')+'>Last '+tf+'</option>';}).join('')+
            '</select>'+
          '</div>'+
          '<div class="v2-report-opt-row">'+
            '<label class="v2-opt-lbl">TLP</label>'+
            '<select class="v2-graph-select" onchange="window._cdwieSetReportTLP(this.value)">'+
              ['white','green','amber','red'].map(function(tlp){return'<option value="'+tlp+'"'+(_s.report.tlp===tlp?' selected':'')+'>TLP:'+tlp.toUpperCase()+'</option>';}).join('')+
            '</select>'+
          '</div>'+
        '</div>'+
        '<div class="v2-report-sections"><h4>Sections</h4>'+sectionItems+'</div>'+
        '<div class="v2-report-actions">'+
          '<button class="v2-btn v2-btn-primary" onclick="window._cdwieGenerateReport()"><i class="fas fa-magic"></i> Generate Report</button>'+
          '<button class="v2-btn v2-btn-ghost" onclick="window._cdwieExportReport(\'pdf\')"><i class="fas fa-file-pdf"></i> PDF</button>'+
          '<button class="v2-btn v2-btn-ghost" onclick="window._cdwieExportReport(\'stix\')"><i class="fas fa-code"></i> STIX</button>'+
          '<button class="v2-btn v2-btn-ghost" onclick="window._cdwieExportReport(\'json\')"><i class="fas fa-brackets-curly"></i> JSON</button>'+
        '</div>'+
      '</div>'+
      '<div class="v2-report-preview" id="v2-report-preview">'+
        '<div class="v2-report-placeholder"><i class="fas fa-file-contract" style="font-size:40px;color:#14b8a620;margin-bottom:12px"></i><br>Configure and generate a report</div>'+
      '</div>'+
    '</div>'+
  '</div>';
}
window._cdwieSetReportType=function(t){_s.report.type=t;_qsa('.v2-rtype-card').forEach(function(c){c.classList.toggle('active',c.querySelector('.v2-rtype-label').textContent.toLowerCase().includes(t.replace(/_/g,' ')));});};
window._cdwieSetReportTF=function(tf){_s.report.timeframe=tf;};
window._cdwieSetReportTLP=function(tlp){_s.report.tlp=tlp;};
window._cdwieToggleSection=function(k,v){_s.report.sections[k]=v;};
window._cdwieGenerateReport=function(){
  var prev=document.getElementById('v2-report-preview');if(!prev)return;
  prev.innerHTML='<div class="v2-loading"><div class="v2-spinner"></div><div style="color:#94a3b8">Generating report\u2026</div></div>';
  _s.report.version++;
  var ver=_s.report.version;
  setTimeout(function(){
    if(_s.report.version!==ver)return;/* cancelled */
    var now=new Date().toISOString().split('T')[0];
    var tlpColor={white:'#94a3b8',green:'#22c55e',amber:'#f59e0b',red:'#ef4444'}[_s.report.tlp]||'#94a3b8';
    var activeCampaigns=DW2_CAMPAIGNS.filter(function(c){return c.prob>=60;});
    var topActors=Object.values(DW2_ACTORS).filter(function(a){return a.threat==='CRITICAL';});
    var sections=_s.report.sections;
    var html='<div class="v2-report-doc">'+
      '<div class="v2-report-doc-header">'+
        '<div style="display:flex;justify-content:space-between;align-items:center">'+
          '<div><div class="v2-report-doc-title">'+_e({'executive':'Executive Threat Intelligence Report','technical':'Technical Deep-Dive Analysis','actor':'Threat Actor Dossier','campaign':'Campaign Analysis Report','ioc':'IOC Indicator Bulletin'}[_s.report.type]||'Threat Intelligence Report')+'</div>'+
          '<div style="color:#475569;font-size:12px;margin-top:4px">Generated: '+now+' \u00b7 Timeframe: '+_s.report.timeframe+' \u00b7 Wadjet-Eye AI v25.0</div></div>'+
          '<span class="v2-tlp-badge" style="background:'+tlpColor+'22;color:'+tlpColor+';border:1px solid '+tlpColor+'44">TLP:'+_s.report.tlp.toUpperCase()+'</span>'+
        '</div>'+
      '</div>';
    if(sections.exec_summary){
      html+='<div class="v2-report-section"><h2><i class="fas fa-chart-pie"></i> Executive Summary</h2>'+
        '<p>The global threat landscape for the period analyzed remains at <strong style="color:#f97316">ELEVATED</strong> risk (score: 74/100). '+activeCampaigns.length+' active campaigns have been confirmed, with <strong>'+activeCampaigns.filter(function(c){return c.confidence==='CRITICAL';}).length+' classified as CRITICAL confidence</strong>. Immediate action is required on IRON RANSOM (LockBit 4.0) lateral movement, currently in progress.</p>'+
        '<div class="v2-report-kpi-row">'+
          '<div class="v2-report-kpi"><div class="v2-report-kpi-val" style="color:#ef4444">'+activeCampaigns.length+'</div><div class="v2-report-kpi-lbl">Active Campaigns</div></div>'+
          '<div class="v2-report-kpi"><div class="v2-report-kpi-val" style="color:#f97316">'+topActors.length+'</div><div class="v2-report-kpi-lbl">Critical Actors</div></div>'+
          '<div class="v2-report-kpi"><div class="v2-report-kpi-val" style="color:#eab308">74</div><div class="v2-report-kpi-lbl">Global Risk Score</div></div>'+
          '<div class="v2-report-kpi"><div class="v2-report-kpi-val" style="color:#a855f7">'+_s.kpis.queries.toLocaleString()+'</div><div class="v2-report-kpi-lbl">AI Queries Run</div></div>'+
        '</div>'+
      '</div>';
    }
    if(sections.campaign_analysis){
      html+='<div class="v2-report-section"><h2><i class="fas fa-crosshairs"></i> Active Campaign Analysis</h2>'+
        activeCampaigns.map(function(c){
          var cc=c.confidence==='CRITICAL'?'#ef4444':c.confidence==='HIGH'?'#f97316':'#eab308';
          return'<div class="v2-report-campaign-row">'+
            '<span class="v2-badge" style="background:'+cc+'22;color:'+cc+'">'+c.confidence+'</span>'+
            '<strong>'+_e(c.name)+'</strong> \u2014 '+_e(c.group)+' \u00b7 Stage: '+_e(c.stages[c.currentStage].name)+' \u00b7 ETA: '+_e(c.eta)+' \u00b7 <span style="color:'+cc+'">'+c.prob+'% escalation</span>'+
          '</div>';
        }).join('')+
      '</div>';
    }
    if(sections.actor_profiles){
      html+='<div class="v2-report-section"><h2><i class="fas fa-user-secret"></i> Critical Threat Actor Profiles</h2>'+
        topActors.map(function(a){
          return'<div class="v2-report-actor-row" style="border-left:3px solid '+a.color+';padding-left:12px;margin-bottom:14px">'+
            '<strong style="color:'+a.color+'">'+a.flag+' '+_e(a.name)+'</strong> \u2014 '+_e(a.alias)+'<br>'+
            '<span style="color:#94a3b8;font-size:12px">Sponsor: '+_e(a.sponsor)+' \u00b7 Confidence: '+a.confidence+'% \u00b7 Active: '+_e(a.active)+'</span><br>'+
            '<span style="color:#64748b;font-size:12px">'+_e(a.desc.slice(0,120))+'...</span>'+
          '</div>';
        }).join('')+
      '</div>';
    }
    if(sections.recommendations){
      html+='<div class="v2-report-section"><h2><i class="fas fa-shield-alt"></i> Priority Recommendations</h2>'+
        ['<strong>CRITICAL \u2014 Immediate:</strong> Isolate LockBit lateral movement (IRON RANSOM). Snapshot all critical VMs. Engage IR team.',
         '<strong>HIGH \u2014 24 hours:</strong> Deploy APT29 HAMMERTOSS v4 YARA rules to EDR. MFA on all privileged accounts.',
         '<strong>HIGH \u2014 72 hours:</strong> Patch CVE-2024-21887 (Ivanti) on all internet-facing appliances.',
         '<strong>MEDIUM \u2014 7 days:</strong> Audit service accounts for FIN7 GRIFFON JS execution patterns.',
         '<strong>MEDIUM \u2014 30 days:</strong> Review and update dark web monitoring keyword lists.'].map(function(r,i){
          return'<div class="v2-report-rec"><span class="v2-defense-num">'+(i+1)+'</span><span>'+r+'</span></div>';
        }).join('')+
      '</div>';
    }
    if(sections.ioc_list){
      html+='<div class="v2-report-section"><h2><i class="fas fa-fingerprint"></i> IOC Digest</h2>'+
        ['lockbit4[.]onion','195.54.162.88','svr-proxy[.]net','40.127.235.1','payment-process[.]net','GRIFFON.js.b64','HAMMERTOSS_v4.dll (MD5: a3b7c2...)','ShadowPad_cfg.bin','ExMatter_v4.exe','blockchain-update.*.com'].map(function(ioc){return'<code class="v2-ioc-tag">'+_e(ioc)+'</code>';}).join(' ')+
      '</div>';
    }
    html+='</div>';
    prev.innerHTML=html;
    _s.kpis.reports++;
    var rEl=document.getElementById('kpi-reports');if(rEl)_flipNum(rEl,_s.kpis.reports);
    _toast('Report generated \u2014 TLP:'+_s.report.tlp.toUpperCase(),'success');
  },2200);
};
window._cdwieExportReport=function(fmt){
  if(!_s.report.sections.exec_summary){_toast('Generate a report first','warning');return;}
  _toast('Exporting as '+fmt.toUpperCase()+'\u2026','info');
  setTimeout(function(){_toast(fmt.toUpperCase()+' export ready for download','success');},1200);
};

/* ──────────────────────────── §20  HEADER BUTTON HANDLERS ───────────────── */
window._cdwiev2FeedToggle=function(){_cdwieTab('dark-feed');};
window._cdwiev2AlertRules=function(){_toast('Alert Rules panel \u2014 coming in v2.1','info');};
window._cdwiev2Investigate=function(){_toast('Investigation Mode \u2014 launch full-screen analyst workspace','info');};

/* ──────────────────────────── §21  IIFE CLOSE ───────────────────────────── */
})(window);
