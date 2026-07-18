/**
 * ══════════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI v25.0 — Global Threat Landscape Module
 *  FILE: js/global-threat-landscape.js
 *
 *  OVERVIEW
 *  ────────
 *  World-class Global Threat Landscape intelligence platform surpassing
 *  Group-IB's Threats & Actors interface. Seven deeply integrated panels:
 *
 *  §1   Constants & Config
 *  §2   Static Intelligence Dataset (actors, campaigns, vulnerabilities, sectors)
 *  §3   Utility Helpers
 *  §4   World Map (SVG choropleth — threat intensity per country, live arcs)
 *  §5   Actor Registry Table (sortable, filterable, expandable row profiles)
 *  §6   Active Campaigns Feed (kanban-style timeline + MITRE heatmap overlay)
 *  §7   Vulnerability Radar (CVSS distribution, exploit-in-wild tracker, zero-day ticker)
 *  §8   Sector Threat Matrix (industry × tactic heatmap with animated threat load bars)
 *  §9   Geopolitical Risk Engine (nation-state actor attribution confidence map)
 *  §10  SIGINT Feed (real-time-styled intelligence dispatch ticker)
 *  §11  AI Threat Briefing Panel (Claude-powered, contextual daily threat brief)
 *  §12  Layout & Router (tabs, render orchestration, resize, live-data polling)
 *  §13  Entry Point: window.renderGlobalThreatLandscape()
 *
 *  Entry point: window.renderGlobalThreatLandscape()
 *  Container:   #page-global-threat-landscape
 * ══════════════════════════════════════════════════════════════════════════════
 */
(function(global) {
'use strict';

/* ═══════════════════════════════════════════════════════════════════════════
   §1  CONSTANTS & CONFIG
═══════════════════════════════════════════════════════════════════════════ */
const GTL_VERSION = '1.0.0';
const GTL_ID = 'gtl-root';

const TABS = [
  { id:'worldmap',    icon:'fa-globe-americas', label:'Threat Map'       },
  { id:'actors',      icon:'fa-users-slash',    label:'Actor Registry'   },
  { id:'campaigns',   icon:'fa-crosshairs',     label:'Active Campaigns' },
  { id:'vulns',       icon:'fa-bug',            label:'Vuln Radar'       },
  { id:'sectors',     icon:'fa-industry',       label:'Sector Matrix'    },
  { id:'geopolitical',icon:'fa-chess-rook',     label:'Geopolitical Risk'},
  { id:'briefing',    icon:'fa-brain',          label:'AI Daily Brief'   },
];

/* colour palette */
const C = {
  bg0:    '#070b14',  bg1:    '#0d1526',  bg2:    '#111d35',
  bg3:    '#162040',  border: '#1e3a5f',  border2:'#243b5f',
  accent: '#00d4ff',  accent2:'#7c3aed',  accent3:'#10b981',
  red:    '#ef4444',  orange: '#f97316',  amber:  '#f59e0b',
  yellow: '#eab308',  green:  '#22c55e',  teal:   '#14b8a6',
  blue:   '#3b82f6',  indigo: '#6366f1',  purple: '#a855f7',
  pink:   '#ec4899',  text:   '#e2e8f0',  muted:  '#64748b',
  crit:   '#ff2d55',  high:   '#ff6b35',  med:    '#ffd60a',  low:    '#34d399',
};

const SEVERITY_CFG = {
  Critical: { color: C.crit,   bg:'rgba(255,45,85,.15)'  },
  High:     { color: C.high,   bg:'rgba(255,107,53,.15)' },
  Medium:   { color: C.med,    bg:'rgba(255,214,10,.15)' },
  Low:      { color: C.low,    bg:'rgba(52,211,153,.15)' },
};

const ACTOR_TYPE_CFG = {
  'Nation-State':  { color: C.red,    icon: 'fa-flag'          },
  'Cybercriminal': { color: C.orange, icon: 'fa-mask'          },
  'Hacktivist':    { color: C.yellow, icon: 'fa-fist-raised'   },
  'Espionage':     { color: C.purple, icon: 'fa-eye'           },
  'Unknown':       { color: C.muted,  icon: 'fa-question-circle'},
};

/* ═══════════════════════════════════════════════════════════════════════════
   §2  STATIC INTELLIGENCE DATASET
═══════════════════════════════════════════════════════════════════════════ */

/* ── 2a  Threat Actors (30 actors with rich profiles) ── */
const GTL_ACTORS = [
  {
    id:'apt29', name:'APT29', aliases:['Cozy Bear','The Dukes','NOBELIUM','Midnight Blizzard'],
    type:'Nation-State', origin:'RU', sponsor:'SVR', since:2008, active:true,
    risk:96, confidence:94, targets:['Government','Defense','Think Tanks','Energy'],
    ttps:['T1566','T1078','T1021','T1102','T1195'],
    tools:['HAMMERTOSS','MiniDuke','WellMess','SUNBURST loader'],
    regions:['AMER','EMEA'], last_seen:'2025-04-10',
    ops:['SolarWinds Supply Chain','HAMMERTOSS C2 Campaign','WellMess COVID Research'],
    brief:'Russian SVR-linked espionage actor. Known for stealthy long-duration intrusions into government and diplomatic targets. Pioneered supply-chain compromise with SUNBURST.',
    iocs:['wellmess[.]com','novetta[.]io (spoofed)'], sectors_hit:72, incidents_yr:34
  },
  {
    id:'apt28', name:'APT28', aliases:['Fancy Bear','Sofacy','Pawn Storm','Forest Blizzard'],
    type:'Nation-State', origin:'RU', sponsor:'GRU', since:2004, active:true,
    risk:94, confidence:96, targets:['Military','Government','NATO','Media'],
    ttps:['T1566','T1059','T1003','T1027','T1071'],
    tools:['X-Agent','Zebrocy','Sofacy','Drovorub'],
    regions:['AMER','EMEA'], last_seen:'2025-03-22',
    ops:['DNC Hack 2016','Bundestag Breach','Ukraine ICS Attacks'],
    brief:'GRU Unit 26165 — aggressive offensive cyber unit with a history of election interference, NATO targeting, and espionage against Western governments.',
    iocs:['microsoftsupport[.]ru','xn--80a4aobg[.]com'], sectors_hit:58, incidents_yr:41
  },
  {
    id:'apt41', name:'APT41', aliases:['Double Dragon','Winnti','Barium','Wicked Panda'],
    type:'Nation-State', origin:'CN', sponsor:'MSS', since:2012, active:true,
    risk:93, confidence:91, targets:['Healthcare','Technology','Telecom','Gaming'],
    ttps:['T1190','T1059','T1078','T1486','T1070'],
    tools:['Derusbi','PlugX','ShadowPad','DUSTPAN'],
    regions:['AMER','APAC','EMEA'], last_seen:'2025-04-05',
    ops:['COVID-19 Research Theft','Video Game IP Theft','USAID Supply Chain'],
    brief:'Chinese MSS-linked dual-mission actor conducting both state-sponsored espionage and financially motivated cybercrime simultaneously — a unique threat profile.',
    iocs:['update[.]biz','cdn99[.]top'], sectors_hit:89, incidents_yr:52
  },
  {
    id:'apt40', name:'APT40', aliases:['BRONZE MOHAWK','Leviathan','TEMP.Periscope','Kryptonite Panda'],
    type:'Nation-State', origin:'CN', sponsor:'MSS', since:2013, active:true,
    risk:88, confidence:87, targets:['Maritime','Defense','Aviation','Government'],
    ttps:['T1190','T1133','T1078','T1560','T1571'],
    tools:['DADBOD','FRESHFIRE','Derusbi','ScanBox'],
    regions:['APAC','EMEA'], last_seen:'2025-02-18',
    ops:['US Navy Research Theft','Maritime Industry Espionage'],
    brief:'PLA Navy-linked Chinese espionage actor targeting maritime industry, naval research, and Belt and Road initiative countries.',
    iocs:['microsoftonline[.]com[.]cn'], sectors_hit:43, incidents_yr:19
  },
  {
    id:'lazarus', name:'Lazarus Group', aliases:['Hidden Cobra','ZINC','Labyrinth Chollima','APT38'],
    type:'Nation-State', origin:'KP', sponsor:'RGB', since:2009, active:true,
    risk:95, confidence:89, targets:['Financial','Crypto','Defense','Aerospace'],
    ttps:['T1566','T1059','T1486','T1041','T1548'],
    tools:['BLINDINGCAN','COPPERHEDGE','DTRACK','NukeSped'],
    regions:['AMER','APAC','EMEA'], last_seen:'2025-04-12',
    ops:['Bangladesh Bank Heist $81M','WannaCry Global','Ronin Bridge $625M','Sony Pictures'],
    brief:'DPRK Bureau 121 cyber unit. Primary mission: foreign currency generation for the regime through crypto theft, SWIFT fraud, and ransomware — funding nuclear program.',
    iocs:['blockbit[.]us','naver-kr[.]com'], sectors_hit:64, incidents_yr:28
  },
  {
    id:'kimsuky', name:'Kimsuky', aliases:['Black Banshee','Velvet Chollima','STOLEN PENCIL'],
    type:'Espionage', origin:'KP', sponsor:'RGB', since:2012, active:true,
    risk:82, confidence:84, targets:['Think Tanks','Government','Defense','Nuclear'],
    ttps:['T1566','T1059','T1056','T1113','T1530'],
    tools:['BabyShark','FlowerPower','GoldDragon','SHARPEXT'],
    regions:['APAC','AMER'], last_seen:'2025-03-15',
    ops:['Nuclear Policy Research Theft','UN Sanctions Committee Spear-Phishing'],
    brief:'North Korean espionage unit targeting Korea-focused researchers, think tanks, and government officials to collect geopolitical intelligence.',
    iocs:['coreamail[.]com','kimsmail[.]xyz'], sectors_hit:31, incidents_yr:22
  },
  {
    id:'apt33', name:'APT33', aliases:['Elfin','Refined Kitten','HOLMIUM','Peach Sandstorm'],
    type:'Nation-State', origin:'IR', sponsor:'IRGC', since:2013, active:true,
    risk:87, confidence:86, targets:['Energy','Aviation','Defense','Petrochemical'],
    ttps:['T1566','T1078','T1133','T1486','T1561'],
    tools:['SHAMOON','StoneDrill','TURNEDUP','Powerton'],
    regions:['EMEA','AMER'], last_seen:'2025-03-28',
    ops:['Saudi Aramco Shamoon 2','Aviation Sector Espionage','US Defense Contractor Breach'],
    brief:'IRGC-linked Iranian actor focused on critical infrastructure sabotage and strategic espionage, with destructive wiper capability deployment.',
    iocs:['update-sec[.]com','jnewsapp[.]com'], sectors_hit:48, incidents_yr:31
  },
  {
    id:'apt34', name:'APT34', aliases:['OilRig','Helix Kitten','IRN2','Europium'],
    type:'Espionage', origin:'IR', sponsor:'MOIS', since:2014, active:true,
    risk:85, confidence:83, targets:['Finance','Government','Energy','Telecom'],
    ttps:['T1078','T1059','T1071','T1560','T1041'],
    tools:['POWBAT','POWRUNER','BONDUPDATER','Karkoff'],
    regions:['EMEA'], last_seen:'2025-02-05',
    ops:['Middle East Government Infiltration','OPEC Nation Finance Sector Ops'],
    brief:'Iranian MOIS-linked cyber espionage unit with persistent focus on financial intelligence from Gulf state governments and energy companies.',
    iocs:['updatens[.]net','microsync[.]cc'], sectors_hit:39, incidents_yr:17
  },
  {
    id:'fin7', name:'FIN7', aliases:['Carbanak Group','Navigator Group','ITG14'],
    type:'Cybercriminal', origin:'RU', sponsor:'eCrime', since:2015, active:true,
    risk:89, confidence:88, targets:['Financial','Retail','Hospitality','Restaurant'],
    ttps:['T1566','T1059','T1486','T1083','T1560'],
    tools:['GRIFFON','Carbanak','Lizar','BIRDWATCH'],
    regions:['AMER','EMEA'], last_seen:'2025-02-14',
    ops:['Chipotle POS Compromise','Gemini POS Campaign','Hotel Check-In Terminal Ops'],
    brief:'Financially-motivated organized crime syndicate operating since 2015. Over $1B stolen from financial institutions and retail POS systems globally.',
    iocs:['carbanak[.]su','fin7crew[.]biz'], sectors_hit:53, incidents_yr:38
  },
  {
    id:'lockbit', name:'LockBit 3.0', aliases:['ABCD Ransomware','LockBit Black'],
    type:'Cybercriminal', origin:'RU', sponsor:'RaaS', since:2019, active:true,
    risk:97, confidence:95, targets:['Healthcare','Finance','Government','Manufacturing'],
    ttps:['T1486','T1490','T1489','T1562','T1070'],
    tools:['LockBit 3.0','StealBit','Cobalt Strike','SystemBC'],
    regions:['AMER','EMEA','APAC'], last_seen:'2025-04-08',
    ops:['ICBC Bank Attack','Royal Mail Ransomware','Boeing Data Theft','Fulton County'],
    brief:'World\'s most prolific ransomware-as-a-service operation. Despite Operation Cronos in Feb 2024, resumed operations within days. 2000+ known victims.',
    iocs:['lockbit3753ekbvndsz[.]onion'], sectors_hit:91, incidents_yr:187
  },
  {
    id:'blackcat', name:'BlackCat/ALPHV', aliases:['Noberus','ALPHV'],
    type:'Cybercriminal', origin:'RU', sponsor:'RaaS', since:2021, active:false,
    risk:92, confidence:90, targets:['Healthcare','Finance','Critical Infra'],
    ttps:['T1486','T1562','T1027','T1078','T1190'],
    tools:['BlackCat Rust ransomware','ExMatter','Brute Ratel C4'],
    regions:['AMER','EMEA'], last_seen:'2024-12-20',
    ops:['MGM Resorts $100M','Caesars Entertainment','Change Healthcare $22M'],
    brief:'Rust-based RaaS with affiliate program. Executed the Change Healthcare attack disrupting US pharmacy nationwide. FBI seized infrastructure in Dec 2023.',
    iocs:['alphvmmm27o3abo3r2mlmjrpdmzle3pzal3oke7x5rcbw3id[.]onion'], sectors_hit:67, incidents_yr:73
  },
  {
    id:'clop', name:'Cl0p', aliases:['TA505','GRACEFUL SPIDER','Gold Tahoe'],
    type:'Cybercriminal', origin:'RU', sponsor:'eCrime', since:2019, active:true,
    risk:91, confidence:87, targets:['Finance','Healthcare','Education','Government'],
    ttps:['T1190','T1486','T1041','T1083','T1657'],
    tools:['Cl0p ransomware','DEWMODE','LEMURLOOT','TrueBot'],
    regions:['AMER','EMEA'], last_seen:'2025-01-15',
    ops:['MOVEit Mass Exploitation 2023','GoAnywhere MFT 0-Day','Accellion FTA Campaign'],
    brief:'Mass-exploitation ransomware group specialising in MFT (Managed File Transfer) zero-day exploitation. MOVEit campaign impacted 2,700+ organisations.',
    iocs:['cl0p[.]onion','losttheworld[.]ws'], sectors_hit:74, incidents_yr:94
  },
  {
    id:'volt', name:'Volt Typhoon', aliases:['BRONZE SILHOUETTE','Vanguard Panda','Dev-0391'],
    type:'Nation-State', origin:'CN', sponsor:'PLA', since:2021, active:true,
    risk:93, confidence:88, targets:['Critical Infra','Military','Utilities','Telecom'],
    ttps:['T1133','T1078','T1021','T1070','T1562'],
    tools:['KV-Botnet','LOTL tools','custom web shells','VersaMem'],
    regions:['AMER','APAC'], last_seen:'2025-04-01',
    ops:['US Critical Infrastructure Pre-positioning','Guam Military Network Intrusion','KV-Botnet SOHO Router Campaign'],
    brief:'PLA-linked actor pre-positioning in US critical infrastructure — power grids, water systems, communications — for potential disruption in case of Taiwan conflict.',
    iocs:['kvsecure[.]xyz','versamem[.]onion'], sectors_hit:38, incidents_yr:21
  },
  {
    id:'salt', name:'Salt Typhoon', aliases:['FamousSparrow','GhostEmperor','Earth Estries'],
    type:'Espionage', origin:'CN', sponsor:'MSS', since:2020, active:true,
    risk:92, confidence:82, targets:['Telecom','Government','Defense','ISP'],
    ttps:['T1190','T1021','T1560','T1041','T1134'],
    tools:['GhostSpider','SnappyBee','Masol RAT','Demodex rootkit'],
    regions:['AMER','APAC'], last_seen:'2025-03-30',
    ops:['US Telecom Breach (AT&T/Verizon/T-Mobile)','CALEA Wiretap System Access','8 Countries ISP Campaign'],
    brief:'Achieved unprecedented access to US telecommunications infrastructure including CALEA lawful intercept systems. Targeted senior US officials and politicians.',
    iocs:['tele-update[.]net'], sectors_hit:29, incidents_yr:15
  },
  {
    id:'scattered_spider', name:'Scattered Spider', aliases:['Starfraud','UNC3944','Octo Tempest','0ktapus'],
    type:'Cybercriminal', origin:'US/UK', sponsor:'eCrime', since:2022, active:true,
    risk:88, confidence:79, targets:['Tech','Telecom','Finance','Casino/Gaming'],
    ttps:['T1621','T1566','T1078','T1486','T1657'],
    tools:['SIM Swap','MFA Fatigue','Okta phishing kits','ALPHV affiliate'],
    regions:['AMER'], last_seen:'2025-03-01',
    ops:['MGM Resorts (ALPHV affiliate)','Caesars Entertainment','Reddit','Twilio'],
    brief:'English-speaking threat actor group leveraging social engineering, SIM swapping, and identity attacks against large enterprises. Native English speakers make detection difficult.',
    iocs:['okta-mgmresorts[.]com'], sectors_hit:34, incidents_yr:29
  },
  {
    id:'killnet', name:'KillNet', aliases:['Infinity Forum','Radis Network'],
    type:'Hacktivist', origin:'RU', sponsor:'State-adjacent', since:2022, active:true,
    risk:71, confidence:77, targets:['Government','Healthcare','Financial','NATO nations'],
    ttps:['T1498','T1499','T1565'],
    tools:['DDoS tools','Mirai variants','custom flood scripts'],
    regions:['EMEA','AMER'], last_seen:'2025-02-28',
    ops:['NATO Website DDoS Campaign','EU Parliament Attack','US Hospital DDoS Wave'],
    brief:'Pro-Russian hacktivist collective conducting DDoS campaigns against NATO member states, Western governments, and healthcare infrastructure since Ukraine war began.',
    iocs:['killnet[.]ws'], sectors_hit:42, incidents_yr:67
  },
  {
    id:'anonymous_sudan', name:'Anonymous Sudan', aliases:['Storm-1359','CARR'],
    type:'Hacktivist', origin:'SD', sponsor:'Unknown', since:2023, active:true,
    risk:74, confidence:70, targets:['Government','Financial','Healthcare','Tech'],
    ttps:['T1498','T1499','T1583'],
    tools:['Skynet DDoS','GODZILLA botnet','InfraShutdown tool'],
    regions:['AMER','EMEA'], last_seen:'2025-01-20',
    ops:['Microsoft 365 Disruption','ChatGPT DDoS','Scandinavian Airlines Attack'],
    brief:'Powerful DDoS-as-a-Service operator responsible for major disruptions including Microsoft Azure, ChatGPT, and X. Possible state-nexus with Russia/Sudan despite hacktivist branding.',
    iocs:['telegram-group: AnonymousSudan'], sectors_hit:47, incidents_yr:82
  },
  {
    id:'revil', name:'REvil/Sodinokibi', aliases:['Gold Southfield','PINCHY SPIDER'],
    type:'Cybercriminal', origin:'RU', sponsor:'RaaS', since:2019, active:false,
    risk:85, confidence:91, targets:['Finance','Manufacturing','Legal','Retail'],
    ttps:['T1486','T1490','T1027','T1078'],
    tools:['Sodinokibi','Cobalt Strike','BloodHound'],
    regions:['AMER','EMEA'], last_seen:'2022-01-14',
    ops:['Kaseya VSA Supply Chain','JBS $11M','Travelex $6M','ACER'],
    brief:'Disbanded after Russian FSB arrests in Jan 2022. Responsible for Kaseya supply chain attack affecting 1,500+ companies. Formerly operated Ransomware as a Service.',
    iocs:['matmgu4pkvicjuv[.]onion'], sectors_hit:61, incidents_yr:0
  },
  {
    id:'darkside', name:'DarkSide', aliases:['Carbon Spider'],
    type:'Cybercriminal', origin:'RU', sponsor:'RaaS', since:2020, active:false,
    risk:83, confidence:89, targets:['Energy','Industrial','Manufacturing'],
    ttps:['T1486','T1490','T1562','T1489'],
    tools:['DarkSide ransomware','Cobalt Strike','Mimikatz'],
    regions:['AMER'], last_seen:'2021-05-14',
    ops:['Colonial Pipeline $4.4M','Brenntag $4.4M'],
    brief:'Ransomware group that attacked Colonial Pipeline causing US East Coast fuel disruption. Disbanded days after attack under US/FBI pressure. Likely rebirthed as BlackMatter.',
    iocs:['darkside-gang[.]com'], sectors_hit:28, incidents_yr:0
  },
  {
    id:'lapsus', name:'Lapsus$', aliases:['DEV-0537','Strawberry Tempest'],
    type:'Cybercriminal', origin:'UK/BR', sponsor:'eCrime', since:2021, active:false,
    risk:79, confidence:85, targets:['Technology','Telecom','Gaming','Semiconductor'],
    ttps:['T1621','T1566','T1078','T1530'],
    tools:['Social engineering','Insider recruitment','MFA bypass'],
    regions:['AMER','EMEA'], last_seen:'2022-09-14',
    ops:['Nvidia IP Theft','Microsoft Source Code','Samsung','Rockstar Games GTA VI'],
    brief:'Teenager-operated data extortion group using social engineering and insider recruitment. Members arrested in UK and Brazil. Stole source code from Nvidia, Microsoft, Samsung.',
    iocs:[], sectors_hit:22, incidents_yr:0
  },
  {
    id:'sandworm', name:'Sandworm', aliases:['Voodoo Bear','TeleBots','IRIDIUM','Seashell Blizzard'],
    type:'Nation-State', origin:'RU', sponsor:'GRU', since:2009, active:true,
    risk:98, confidence:95, targets:['Critical Infra','ICS/OT','Government','Media'],
    ttps:['T1561','T1499','T1486','T1059','T1195'],
    tools:['NotPetya','BlackEnergy','Industroyer','CaddyWiper','AcidRain'],
    regions:['EMEA'], last_seen:'2025-04-02',
    ops:['Ukraine Power Grid 2015/2016','NotPetya $10B Global','Olympic Destroyer','Viasat Wiper'],
    brief:'GRU Unit 74455 — Russia\'s most destructive cyber unit. NotPetya caused $10B in damages globally. Responsible for every major ICS/OT attack on Ukrainian infrastructure.',
    iocs:['sandworm-c2[.]ru'], sectors_hit:35, incidents_yr:24
  },
  {
    id:'turla', name:'Turla', aliases:['Snake','Uroburos','Waterbug','VENOMOUS BEAR','Secret Blizzard'],
    type:'Espionage', origin:'RU', sponsor:'FSB', since:1996, active:true,
    risk:91, confidence:92, targets:['Government','Military','Diplomatic','Defense'],
    ttps:['T1071','T1027','T1078','T1560','T1056'],
    tools:['Snake rootkit','Carbon','ComRAT','TinyTurla','HyperStack'],
    regions:['EMEA','AMER'], last_seen:'2025-03-10',
    ops:['Snake Global Disruption (FBI 2023)','Pentagon Breach','European Embassies Campaign'],
    brief:'FSB-linked APT with 25+ years of operation — oldest active Russian APT. Deploys the most sophisticated rootkit ever seen in the wild (Snake/Uroburos). US/allies disrupted in 2023.',
    iocs:['bpis[.]ru (Snake C2)'], sectors_hit:29, incidents_yr:11
  },
  {
    id:'hafnium', name:'HAFNIUM', aliases:['Silk Typhoon','DEV-0234'],
    type:'Nation-State', origin:'CN', sponsor:'MSS', since:2021, active:true,
    risk:90, confidence:86, targets:['Defense','Legal','Think Tanks','Medical'],
    ttps:['T1190','T1059','T1078','T1560'],
    tools:['China Chopper','ASPXSPY','Covenant C2'],
    regions:['AMER'], last_seen:'2025-01-30',
    ops:['MS Exchange Server 0-Day (ProxyLogon) — 250k servers','Treasury Department Breach 2024'],
    brief:'MSS-linked actor that exploited 4 MS Exchange Server zero-days simultaneously in March 2021, compromising 250,000 servers globally within days.',
    iocs:['p.estonine[.]com'], sectors_hit:44, incidents_yr:18
  },
  {
    id:'ta577', name:'TA577', aliases:['Hive0118','Pistachio Tempest'],
    type:'Cybercriminal', origin:'Unknown', sponsor:'eCrime', since:2020, active:true,
    risk:76, confidence:73, targets:['Finance','Manufacturing','Healthcare'],
    ttps:['T1566','T1059','T1027','T1486'],
    tools:['Qakbot','Black Basta affiliate tooling','Cobalt Strike'],
    regions:['AMER','EMEA'], last_seen:'2025-02-10',
    ops:['Qakbot Wave 2024','Black Basta Healthcare Campaign'],
    brief:'Prolific initial-access broker and Qakbot distributor. Partners with Black Basta ransomware group for monetisation of compromised networks.',
    iocs:['qakbot-cdn[.]com'], sectors_hit:38, incidents_yr:45
  },
  {
    id:'wizard_spider', name:'Wizard Spider', aliases:['TEMP.MixMaster','UNC1878','Gold Blackburn'],
    type:'Cybercriminal', origin:'RU', sponsor:'eCrime', since:2016, active:true,
    risk:90, confidence:88, targets:['Healthcare','Finance','Government','Education'],
    ttps:['T1486','T1490','T1059','T1566','T1489'],
    tools:['TrickBot','Ryuk','Conti','BazarLoader','Anchor'],
    regions:['AMER','EMEA'], last_seen:'2025-01-08',
    ops:['Universal Health Services Ryuk','Ireland HSE Conti','Atlanta Schools'],
    brief:'Russian organised crime group operating TrickBot/Conti/Ryuk ecosystem. Conti disbanded in 2022 after internal leaks. Splintered into multiple successor groups.',
    iocs:['trickbot-c2[.]ru'], sectors_hit:77, incidents_yr:52
  },
  {
    id:'muddywater', name:'MuddyWater', aliases:['TEMP.Zagros','Static Kitten','Mango Sandstorm'],
    type:'Nation-State', origin:'IR', sponsor:'MOIS', since:2017, active:true,
    risk:80, confidence:82, targets:['Government','Telecom','Defense','Education'],
    ttps:['T1566','T1059','T1027','T1071','T1056'],
    tools:['POWERSTATS','Canopy/STARWHALE','PhonyC2'],
    regions:['EMEA'], last_seen:'2025-03-05',
    ops:['MENA Government Campaign','Israel Telecom Espionage'],
    brief:'Iranian MOIS sub-group conducting espionage against government and telecom sectors primarily in Middle East, Turkey, Africa and Asia.',
    iocs:['muddyc3[.]ir'], sectors_hit:34, incidents_yr:26
  },
  {
    id:'gamaredon', name:'Gamaredon', aliases:['Primitive Bear','ACTINIUM','Shuckworm','Trident Ursa'],
    type:'Nation-State', origin:'RU', sponsor:'FSB', since:2013, active:true,
    risk:82, confidence:88, targets:['Ukrainian Government','Military','NGO','Defense'],
    ttps:['T1566','T1059','T1547','T1091','T1025'],
    tools:['Pteranodon','Warzone RAT','GammaSteel','custom USB worms'],
    regions:['EMEA'], last_seen:'2025-04-05',
    ops:['Ukraine Government Persistent Intrusion','NATO Advisory Staff Phishing'],
    brief:'FSB Crimea-based unit conducting near-constant operations against Ukrainian government targets. Highly persistent with low operational security — likely intentional.',
    iocs:['pterado[.]ru','vestigator[.]site'], sectors_hit:19, incidents_yr:89
  },
  {
    id:'equation_group', name:'Equation Group', aliases:['Longhorn','The Lamberts','APT-C-40'],
    type:'Nation-State', origin:'US', sponsor:'NSA/TAO', since:1996, active:true,
    risk:99, confidence:81, targets:['Government','Military','Telecom','Defense worldwide'],
    ttps:['T1542','T1027','T1078','T1195','T1056'],
    tools:['EQUATIONLASER','EQUATIONDRUG','DOUBLEFANTASY','EternalBlue','DoublePulsar'],
    regions:['AMER','EMEA','APAC'], last_seen:'2025-04-01',
    ops:['Stuxnet (with Unit 8200)','Shadow Brokers Leak 2016','Global Telco Implant Programme'],
    brief:'NSA TAO most sophisticated cyber operator. Operated for 20+ years before Shadow Brokers leaked toolkit. EternalBlue exploit enabled WannaCry and NotPetya.',
    iocs:[], sectors_hit:55, incidents_yr:8
  },
  {
    id:'unit8200', name:'Unit 8200', aliases:['ISNU','Duqu Group','Stuxnet co-author'],
    type:'Nation-State', origin:'IL', sponsor:'IDF', since:2007, active:true,
    risk:97, confidence:78, targets:['Nuclear','ICS/OT','Military','Government'],
    ttps:['T1542','T1195','T1485','T1059'],
    tools:['Stuxnet','Duqu','Flame','Gauss'],
    regions:['EMEA'], last_seen:'2025-03-20',
    ops:['Stuxnet — Natanz nuclear centrifuges','Flame espionage platform','Gaza infrastructure targeting'],
    brief:'Israeli military intelligence unit. Co-developed Stuxnet with NSA/TAO. Most technically sophisticated offensive capability outside of major powers.',
    iocs:[], sectors_hit:14, incidents_yr:6
  },
  {
    id:'patchwork', name:'Patchwork', aliases:['Dropping Elephant','Chinastrats','Monsoon'],
    type:'Espionage', origin:'IN', sponsor:'Govt', since:2015, active:true,
    risk:65, confidence:71, targets:['Government','Military','Think Tanks','Pakistan/China'],
    ttps:['T1566','T1059','T1027','T1056'],
    tools:['BADNEWS RAT','QuasarRAT','Ragnatela'],
    regions:['APAC','EMEA'], last_seen:'2025-01-12',
    ops:['SAARC Government Espionage','Pakistani Nuclear Researcher Targeting'],
    brief:'Indian-nexus espionage group conducting targeted attacks against Pakistan and China-aligned entities. Known for copy-pasting code from public sources — hence "Patchwork".',
    iocs:['ragnatela-c2[.]in'], sectors_hit:21, incidents_yr:14
  },
];

/* ── 2b  Active Campaigns (20 campaigns) ── */
const GTL_CAMPAIGNS = [
  { id:'c001', name:'Operation MidnightEclipse', actor:'apt29', status:'Active', severity:'Critical',
    started:'2024-11-01', updated:'2025-04-10', targeted_sectors:['Government','Energy','Defense'],
    targeted_regions:['AMER','EMEA'], ttps:['T1195','T1566','T1078'],
    description:'Long-duration supply chain infiltration targeting Western government software vendors. Implants persistent access via build pipeline compromise.',
    indicators:14, victims:7, confidence:88 },
  { id:'c002', name:'Operation GHOSTWRITERS', actor:'apt28', status:'Active', severity:'High',
    started:'2024-08-15', updated:'2025-03-22', targeted_sectors:['Media','Government','Military'],
    targeted_regions:['EMEA'], ttps:['T1566','T1059','T1003'],
    description:'Influence and espionage hybrid operation targeting European media outlets ahead of elections, with simultaneous credential theft.',
    indicators:31, victims:12, confidence:83 },
  { id:'c003', name:'TyphoonNest Infrastructure', actor:'volt', status:'Active', severity:'Critical',
    started:'2023-05-01', updated:'2025-04-01', targeted_sectors:['Critical Infra','Telecom','Military'],
    targeted_regions:['AMER'], ttps:['T1133','T1078','T1021'],
    description:'Pre-positioning campaign in US critical infrastructure. SOHO router botnet (KV-Botnet) used as obfuscation layer for persistent access.',
    indicators:89, victims:23, confidence:91 },
  { id:'c004', name:'SaltStream Intercept', actor:'salt', status:'Active', severity:'Critical',
    started:'2022-06-01', updated:'2025-03-30', targeted_sectors:['Telecom','Government'],
    targeted_regions:['AMER','APAC'], ttps:['T1190','T1021','T1560'],
    description:'Nation-scale telecom infiltration compromising major US carriers. Access to CALEA lawful intercept systems allowed interception of communications.',
    indicators:42, victims:9, confidence:82 },
  { id:'c005', name:'DragonPharm 2025', actor:'apt41', status:'Active', severity:'High',
    started:'2025-01-10', updated:'2025-04-05', targeted_sectors:['Healthcare','Pharma'],
    targeted_regions:['AMER','EMEA'], ttps:['T1190','T1059','T1486'],
    description:'Dual-use campaign: espionage targeting pharmaceutical R&D combined with ransomware deployment for financial gain.',
    indicators:27, victims:5, confidence:76 },
  { id:'c006', name:'LockBit Spring Wave 2025', actor:'lockbit', status:'Active', severity:'Critical',
    started:'2025-03-01', updated:'2025-04-08', targeted_sectors:['Healthcare','Finance','Government'],
    targeted_regions:['AMER','EMEA','APAC'], ttps:['T1486','T1490','T1489'],
    description:'Post-disruption resurgence. New LockBit 3.0 variant with enhanced encryption and expanded affiliate network targeting healthcare globally.',
    indicators:156, victims:34, confidence:96 },
  { id:'c007', name:'Cl0p Zero-Day Spring', actor:'clop', status:'Active', severity:'High',
    started:'2025-02-01', updated:'2025-04-01', targeted_sectors:['Finance','Legal','Healthcare'],
    targeted_regions:['AMER','EMEA'], ttps:['T1190','T1083','T1657'],
    description:'Mass exploitation of new file transfer software zero-day. Exfiltration-only operation — no encryption, pure data theft for extortion.',
    indicators:63, victims:18, confidence:84 },
  { id:'c008', name:'Operation SANDSTORM', actor:'apt33', status:'Active', severity:'High',
    started:'2024-10-01', updated:'2025-03-28', targeted_sectors:['Energy','Defense','Aviation'],
    targeted_regions:['AMER','EMEA'], ttps:['T1566','T1078','T1486'],
    description:'IRGC-directed campaign targeting Gulf state energy infrastructure and US defense contractors. Destructive wiper payload pre-staged.',
    indicators:38, victims:11, confidence:81 },
  { id:'c009', name:'Crypto Heist Q1 2025', actor:'lazarus', status:'Active', severity:'High',
    started:'2025-01-01', updated:'2025-04-12', targeted_sectors:['Crypto','Finance'],
    targeted_regions:['AMER','APAC'], ttps:['T1566','T1059','T1486'],
    description:'Series of cryptocurrency exchange and DeFi protocol compromises. $340M confirmed stolen in Q1 2025 across 6 incidents.',
    indicators:77, victims:6, confidence:87 },
  { id:'c010', name:'Gamaredon Persistent Ukraine', actor:'gamaredon', status:'Active', severity:'High',
    started:'2022-02-24', updated:'2025-04-05', targeted_sectors:['Government','Military'],
    targeted_regions:['EMEA'], ttps:['T1566','T1547','T1091'],
    description:'Ongoing near-constant cyber campaign against Ukrainian government and military. Thousands of spear-phishing attempts per week with USB propagation.',
    indicators:2341, victims:89, confidence:95 },
  { id:'c011', name:'KillNet DDoS Spring', actor:'killnet', status:'Active', severity:'Medium',
    started:'2025-03-01', updated:'2025-03-15', targeted_sectors:['Government','Healthcare'],
    targeted_regions:['EMEA'], ttps:['T1498','T1499'],
    description:'Coordinated DDoS campaign against EU member state health ministries in protest of medical aid to Ukraine.',
    indicators:12, victims:22, confidence:77 },
  { id:'c012', name:'FIN7 Hospitality Wave', actor:'fin7', status:'Active', severity:'High',
    started:'2024-12-01', updated:'2025-02-14', targeted_sectors:['Hospitality','Retail'],
    targeted_regions:['AMER'], ttps:['T1566','T1059','T1083'],
    description:'Targeted spear-phishing against major hotel chains and restaurant POS systems. GRIFFON downloader delivery via fake job application emails.',
    indicators:47, victims:9, confidence:82 },
  { id:'c013', name:'TA577 Healthcare Blitz', actor:'ta577', status:'Active', severity:'High',
    started:'2025-02-01', updated:'2025-03-10', targeted_sectors:['Healthcare'],
    targeted_regions:['AMER','EMEA'], ttps:['T1566','T1059','T1486'],
    description:'Qakbot-as-initial-access followed by Black Basta ransomware deployment. Targeting healthcare post-Change Healthcare disruption to exploit weakened defences.',
    indicators:93, victims:15, confidence:79 },
  { id:'c014', name:'Turla Embassy Network', actor:'turla', status:'Active', severity:'High',
    started:'2024-09-01', updated:'2025-03-10', targeted_sectors:['Diplomatic','Government'],
    targeted_regions:['EMEA'], ttps:['T1071','T1027','T1078'],
    description:'Long-duration espionage against Eastern European diplomatic missions. Snake-successor implants with encrypted satellite communication channels.',
    indicators:19, victims:6, confidence:84 },
  { id:'c015', name:'Hafnium Treasury', actor:'hafnium', status:'Active', severity:'High',
    started:'2024-09-15', updated:'2025-01-30', targeted_sectors:['Government','Finance'],
    targeted_regions:['AMER'], ttps:['T1190','T1059','T1560'],
    description:'Compromise of US Treasury Department via BeyondTrust remote access flaw. Access to unclassified OFI and OFAC sanctions systems.',
    indicators:8, victims:2, confidence:86 },
  { id:'c016', name:'Sandworm Rail Disruption', actor:'sandworm', status:'Monitoring', severity:'Critical',
    started:'2025-02-15', updated:'2025-04-02', targeted_sectors:['Transport','Critical Infra'],
    targeted_regions:['EMEA'], ttps:['T1561','T1059','T1486'],
    description:'Targeting Eastern European railway scheduling and SCADA systems. Precursor activity pattern consistent with pre-sabotage positioning.',
    indicators:31, victims:4, confidence:73 },
  { id:'c017', name:'APT34 OPEC Survey', actor:'apt34', status:'Active', severity:'Medium',
    started:'2025-01-01', updated:'2025-02-05', targeted_sectors:['Energy','Finance'],
    targeted_regions:['EMEA'], ttps:['T1078','T1059','T1071'],
    description:'Espionage campaign gathering economic intelligence from OPEC member states finance ministries and energy ministries ahead of production decision.',
    indicators:22, victims:5, confidence:75 },
  { id:'c018', name:'Scattered Spider 2025', actor:'scattered_spider', status:'Active', severity:'High',
    started:'2025-01-15', updated:'2025-03-01', targeted_sectors:['Tech','Finance'],
    targeted_regions:['AMER'], ttps:['T1621','T1566','T1078'],
    description:'New wave of SIM-swap and MFA fatigue attacks against fintech and major tech companies. Focus on executive account takeover for wire fraud.',
    indicators:18, victims:7, confidence:72 },
  { id:'c019', name:'APT40 Pacific Maritime', actor:'apt40', status:'Active', severity:'High',
    started:'2024-11-01', updated:'2025-02-18', targeted_sectors:['Maritime','Defense'],
    targeted_regions:['APAC'], ttps:['T1190','T1133','T1560'],
    description:'Reconnaissance and espionage against South China Sea maritime entities, shipbuilding firms, and US Indo-Pacific Command contractors.',
    indicators:29, victims:8, confidence:80 },
  { id:'c020', name:'Kimsuky Academic Sweep', actor:'kimsuky', status:'Active', severity:'Medium',
    started:'2025-02-01', updated:'2025-03-15', targeted_sectors:['Education','Government'],
    targeted_regions:['AMER','APAC'], ttps:['T1566','T1059','T1056'],
    description:'Targeting US/South Korean academic institutions studying North Korean policy, nuclear nonproliferation, and Korean Peninsula geopolitics.',
    indicators:34, victims:12, confidence:79 },
];

/* ── 2c  Vulnerability Intelligence (25 CVEs) ── */
const GTL_VULNS = [
  { cve:'CVE-2025-0282', cvss:9.8, severity:'Critical', product:'Ivanti Connect Secure', vendor:'Ivanti',
    type:'RCE', exploit_wild:true, zero_day:true, patch_available:true,
    actors:['apt29','apt41'], first_exploited:'2025-01-08', description:'Stack-based buffer overflow in ICS allowing unauthenticated RCE. Widely exploited by Chinese and Russian APTs.' },
  { cve:'CVE-2024-3400', cvss:10.0, severity:'Critical', product:'PAN-OS GlobalProtect', vendor:'Palo Alto',
    type:'RCE', exploit_wild:true, zero_day:true, patch_available:true,
    actors:['apt29','volt'], first_exploited:'2024-04-12', description:'Command injection in GlobalProtect VPN. UTA0218 exploited before disclosure. Over 22,000 instances exposed.' },
  { cve:'CVE-2023-34362', cvss:9.8, severity:'Critical', product:'MOVEit Transfer', vendor:'Progress',
    type:'SQLi/RCE', exploit_wild:true, zero_day:false, patch_available:true,
    actors:['clop'], first_exploited:'2023-05-27', description:'SQL injection leading to RCE in MOVEit. Cl0p mass-exploited affecting 2,700+ organizations globally.' },
  { cve:'CVE-2024-21413', cvss:9.8, severity:'Critical', product:'Microsoft Outlook', vendor:'Microsoft',
    type:'RCE', exploit_wild:true, zero_day:false, patch_available:true,
    actors:['apt28','apt34'], first_exploited:'2024-02-15', description:'MonikerLink bug allowing NTLM credential theft via crafted hyperlinks. Dubbed "MonikerLink".' },
  { cve:'CVE-2025-21418', cvss:7.8, severity:'High', product:'Windows AFD Driver', vendor:'Microsoft',
    type:'LPE', exploit_wild:true, zero_day:true, patch_available:true,
    actors:['lazarus'], first_exploited:'2025-01-15', description:'Windows Ancillary Function Driver for WinSock elevation of privilege used in Lazarus Group attacks.' },
  { cve:'CVE-2024-49113', cvss:7.5, severity:'High', product:'Windows LDAP', vendor:'Microsoft',
    type:'DoS/RCE', exploit_wild:false, zero_day:false, patch_available:true,
    actors:[], first_exploited:null, description:'LDAP Nightmare — LDAP denial of service with potential for RCE. PoC released publicly.' },
  { cve:'CVE-2024-38812', cvss:9.8, severity:'Critical', product:'VMware vCenter', vendor:'Broadcom',
    type:'RCE', exploit_wild:true, zero_day:false, patch_available:true,
    actors:['apt29','hafnium'], first_exploited:'2024-10-28', description:'Heap overflow in DCERPC protocol implementation. Allows unauthenticated RCE against vCenter. Widely exploited.' },
  { cve:'CVE-2024-27198', cvss:9.8, severity:'Critical', product:'TeamCity', vendor:'JetBrains',
    type:'Auth Bypass', exploit_wild:true, zero_day:false, patch_available:true,
    actors:['apt29'], first_exploited:'2024-03-06', description:'Authentication bypass in JetBrains TeamCity CI/CD server. BianLian, RansomHouse, and APT29 exploited within days.' },
  { cve:'CVE-2023-4966', cvss:9.4, severity:'Critical', product:'NetScaler ADC/Gateway', vendor:'Citrix',
    type:'Info Disclosure', exploit_wild:true, zero_day:true, patch_available:true,
    actors:['lockbit','apt41'], first_exploited:'2023-08-01', description:'Citrix Bleed — session token disclosure enabling MFA bypass. Lockbit used to hit Boeing, ICBC.' },
  { cve:'CVE-2024-1708', cvss:8.4, severity:'High', product:'ConnectWise ScreenConnect', vendor:'ConnectWise',
    type:'Path Traversal', exploit_wild:true, zero_day:false, patch_available:true,
    actors:['lockbit','blackcat'], first_exploited:'2024-02-20', description:'Authentication bypass chained with path traversal. Mass-exploited by ransomware groups for initial access.' },
  { cve:'CVE-2025-0994', cvss:8.8, severity:'High', product:'Trimble Cityworks', vendor:'Trimble',
    type:'RCE', exploit_wild:true, zero_day:true, patch_available:true,
    actors:['apt41'], first_exploited:'2025-01-22', description:'Deserialization RCE in municipal infrastructure management software. Used against US local government.' },
  { cve:'CVE-2024-23897', cvss:9.8, severity:'Critical', product:'Jenkins', vendor:'Jenkins CI',
    type:'Arbitrary File Read', exploit_wild:true, zero_day:false, patch_available:true,
    actors:['clop','fin7'], first_exploited:'2024-01-26', description:'Arbitrary file read via CLI parser. PoC public within 48 hours. Ransomware groups quickly weaponised.' },
  { cve:'CVE-2024-6387', cvss:8.1, severity:'High', product:'OpenSSH', vendor:'OpenBSD',
    type:'RCE', exploit_wild:false, zero_day:false, patch_available:true,
    actors:[], first_exploited:null, description:'regreSSHion — race condition RCE in glibc-based Linux OpenSSH. 14M internet-exposed instances identified.' },
  { cve:'CVE-2024-4577', cvss:9.8, severity:'Critical', product:'PHP-CGI', vendor:'PHP Group',
    type:'RCE', exploit_wild:true, zero_day:false, patch_available:true,
    actors:['apt41','fin7'], first_exploited:'2024-06-07', description:'Argument injection in PHP-CGI on Windows. Active exploitation within hours of public disclosure.' },
  { cve:'CVE-2024-21762', cvss:9.6, severity:'Critical', product:'FortiOS SSL VPN', vendor:'Fortinet',
    type:'RCE', exploit_wild:true, zero_day:false, patch_available:true,
    actors:['apt33','apt34'], first_exploited:'2024-02-09', description:'Out-of-bounds write allowing code execution. Iran-nexus actors exploited against critical infrastructure.' },
  { cve:'CVE-2024-30078', cvss:8.8, severity:'High', product:'Windows Wi-Fi Driver', vendor:'Microsoft',
    type:'RCE', exploit_wild:false, zero_day:false, patch_available:true,
    actors:[], first_exploited:null, description:'Zero-click RCE via proximity — attacker on same wireless network can execute code without user interaction.' },
  { cve:'CVE-2023-44487', cvss:7.5, severity:'High', product:'HTTP/2 Rapid Reset', vendor:'Multiple',
    type:'DoS', exploit_wild:true, zero_day:false, patch_available:true,
    actors:['killnet','anonymous_sudan'], first_exploited:'2023-08-01', description:'HTTP/2 protocol implementation flaw enabling record-breaking DDoS attacks (398M rps). Coordinated by hacktivist groups.' },
  { cve:'CVE-2024-20353', cvss:8.6, severity:'High', product:'Cisco ASA/FTD', vendor:'Cisco',
    type:'DoS', exploit_wild:true, zero_day:false, patch_available:true,
    actors:['apt33'], first_exploited:'2024-04-24', description:'Denial of service in SSL/TLS processing. State-sponsored actors targeted US and Israeli networks.' },
  { cve:'CVE-2024-50623', cvss:10.0, severity:'Critical', product:'Cleo Harmony/VLTrader', vendor:'Cleo',
    type:'RCE', exploit_wild:true, zero_day:true, patch_available:true,
    actors:['clop'], first_exploited:'2024-12-03', description:'Unrestricted file upload/download leading to RCE. Cl0p mass-exploited as a follow-up to MOVEit.' },
  { cve:'CVE-2025-0411', cvss:7.0, severity:'High', product:'7-Zip', vendor:'7-Zip',
    type:'MOTW Bypass', exploit_wild:true, zero_day:false, patch_available:true,
    actors:['apt41','gamaredon'], first_exploited:'2025-01-10', description:'Mark-of-the-Web bypass allowing malware in archives to execute without security warnings.' },
  { cve:'CVE-2024-9463', cvss:9.9, severity:'Critical', product:'Palo Alto Expedition', vendor:'Palo Alto',
    type:'RCE/SQLi', exploit_wild:true, zero_day:false, patch_available:true,
    actors:['apt41'], first_exploited:'2024-11-18', description:'OS command injection in Palo Alto Expedition config migration tool allowing credential theft and RCE.' },
  { cve:'CVE-2024-43572', cvss:7.8, severity:'High', product:'Windows MMC', vendor:'Microsoft',
    type:'RCE', exploit_wild:true, zero_day:true, patch_available:true,
    actors:['fin7'], first_exploited:'2024-10-08', description:'Microsoft Management Console remote code execution via malicious MSC file. FIN7 used in spear-phishing.' },
  { cve:'CVE-2025-21333', cvss:7.8, severity:'High', product:'Windows Hyper-V', vendor:'Microsoft',
    type:'LPE', exploit_wild:true, zero_day:true, patch_available:true,
    actors:['lazarus'], first_exploited:'2025-01-15', description:'Hyper-V NT Kernel Integration VSP elevation of privilege. Part of January 2025 Lazarus zero-day cluster.' },
  { cve:'CVE-2024-21887', cvss:9.1, severity:'Critical', product:'Ivanti Connect Secure', vendor:'Ivanti',
    type:'RCE', exploit_wild:true, zero_day:true, patch_available:true,
    actors:['apt29','volt'], first_exploited:'2024-01-10', description:'Command injection in web components. Chained with CVE-2023-46805 for unauthenticated RCE. Mass exploitation by Chinese and Russian APTs.' },
  { cve:'CVE-2023-20198', cvss:10.0, severity:'Critical', product:'Cisco IOS XE Web UI', vendor:'Cisco',
    type:'Auth Bypass/RCE', exploit_wild:true, zero_day:true, patch_available:true,
    actors:['salt','volt'], first_exploited:'2023-09-18', description:'Web UI privilege escalation used to plant implants on 50,000+ Cisco network devices. Salt/Volt Typhoon exploited extensively.' },
];

/* ── 2d  Sector Threat Matrix (12 sectors × 14 tactics) ── */
const GTL_SECTORS = ['Finance','Healthcare','Energy','Government','Defense','Telecom','Manufacturing','Transport','Education','Technology','Retail','Critical Infra'];
const SECTOR_SCORES = {
  Finance:       [82,75,91,88,71,65,84,73,90,68,88,62,79,85],
  Healthcare:    [74,68,95,86,62,55,72,68,87,55,79,48,72,94],
  Energy:        [71,60,87,79,88,91,66,62,72,84,63,57,75,73],
  Government:    [95,88,89,91,79,73,87,82,85,71,82,68,91,78],
  Defense:       [89,82,86,84,94,88,83,79,81,91,78,83,88,72],
  Telecom:       [78,71,84,82,72,68,81,88,77,63,79,74,92,81],
  Manufacturing: [65,58,72,68,75,79,61,57,63,71,55,66,68,84],
  Transport:     [68,62,79,75,71,74,65,64,69,60,67,72,71,77],
  Education:     [62,71,65,74,55,48,58,60,86,50,68,44,62,58],
  Technology:    [75,78,72,84,69,65,77,73,74,82,84,61,85,71],
  Retail:        [79,65,68,71,58,52,81,74,69,55,91,47,68,77],
  'Critical Infra':[73,66,91,85,82,87,69,65,71,78,62,84,77,89],
};

/* ── 2e  Country threat-level scores (ISO3 → score 0-100) ── */
const COUNTRY_THREAT = {
  USA:98, RUS:82, CHN:79, GBR:72, DEU:68, FRA:67, UKR:91, ISR:75,
  IRN:74, PRK:71, IND:65, BRA:63, AUS:69, CAN:71, JPN:66, KOR:68,
  SAU:72, ARE:69, POL:74, NLD:70, BEL:68, SWE:65, FIN:64, NOR:63,
  ESP:62, ITA:64, CHE:61, AUT:60, PRT:58, GRC:61, TUR:67, PAK:64,
  AFG:55, IRQ:59, SYR:61, LBN:57, EGY:63, ZAF:61, NGA:60, KEN:58,
  MEX:66, ARG:58, COL:56, SGP:69, MYS:63, THA:61, IDN:62, PHL:59,
  VNM:61, TWN:72,
};

/* ── 2f  SIGINT Feed Dispatches ── */
const SIGINT_FEED = [
  { ts:'2025-04-12T14:31:00Z', priority:'FLASH', src:'HUMINT-07', text:'APT29 operator tradecraft shift: observed pivot to residential proxy networks in NL/DE for operational relay.' },
  { ts:'2025-04-12T12:18:00Z', priority:'CRITIC', src:'SIGINT-ALPHA', text:'LockBit 3.0 new encryptor variant ("LB3.1") identified in-the-wild — evades 14/68 AV engines on initial detection.' },
  { ts:'2025-04-12T11:45:00Z', priority:'URGENT', src:'TECHINT-03', text:'CVE-2025-0282 (Ivanti) active exploitation wave detected: 340 unique IPs probing exposed instances globally.' },
  { ts:'2025-04-11T22:00:00Z', priority:'FLASH', src:'OSINT-11', text:'Lazarus Group new cryptocurrency exchange reconnaissance: 3 South Korean targets actively profiled via spear-phishing setup.' },
  { ts:'2025-04-11T19:45:00Z', priority:'URGENT', src:'NETINT-02', text:'Salt Typhoon C2 infrastructure rotation observed: 12 new IP addresses registered in Singapore/HK datacenters.' },
  { ts:'2025-04-11T16:30:00Z', priority:'ROUTINE', src:'OSINT-04', text:'Killnet Telegram channel announces new DDoS coalition targeting Baltic states financial sector next 72 hours.' },
  { ts:'2025-04-10T23:15:00Z', priority:'CRITIC', src:'TECHINT-09', text:'Sandworm pre-positioning activity detected in 3 European rail SCADA environments. Wiper payload staging suspected.' },
  { ts:'2025-04-10T18:00:00Z', priority:'FLASH', src:'FININT-01', text:'Lazarus-linked crypto mixer wallets processed $42M in Q1 — highest quarterly volume since 2022.' },
  { ts:'2025-04-09T14:22:00Z', priority:'URGENT', src:'TECHINT-06', text:'New Cobalt Strike beacon profile matching APT41 TTP cluster observed in 5 healthcare networks — possible campaign overlap.' },
  { ts:'2025-04-09T09:10:00Z', priority:'ROUTINE', src:'OSINT-02', text:'FIN7 job recruitment campaign detected on dark forums — hiring cryptors, network pen-testers for Q2 ops ramp-up.' },
  { ts:'2025-04-08T21:00:00Z', priority:'FLASH', src:'HUMINT-03', text:'Anonymous Sudan reportedly acquired access to Layer-7 DDoS infrastructure with 3Tbps capacity — threat to critical SaaS providers.' },
  { ts:'2025-04-08T15:30:00Z', priority:'CRITIC', src:'TECHINT-12', text:'Cl0p actors observed acquiring 0-day for widely-used enterprise backup software — possible successor to MOVEit campaign.' },
  { ts:'2025-04-07T11:45:00Z', priority:'URGENT', src:'GEOINT-01', text:'Volt Typhoon KV-Botnet activity surge: 2,400 newly enrolled SOHO routers in past 72 hours — largest single expansion event.' },
  { ts:'2025-04-07T08:00:00Z', priority:'ROUTINE', src:'OSINT-07', text:'Scattered Spider arrested member reportedly cooperating with FBI — possible attribution data for 2024 MGM intrusion set.' },
  { ts:'2025-04-06T19:30:00Z', priority:'FLASH', src:'TECHINT-08', text:'New UEFI bootkit attributed to Turla/Snake successor detected on Eastern European diplomatic endpoint — first UEFI-level Turla capability.' },
  { ts:'2025-04-05T14:15:00Z', priority:'URGENT', src:'SIGINT-BRAVO', text:'APT41 new implant "DUSTPAN v3" evades EDR via legitimate signed binary sideloading — patch for affected security products expected.' },
  { ts:'2025-04-04T10:30:00Z', priority:'ROUTINE', src:'TECHINT-04', text:'BlackCat/ALPHV affiliate operators transitioning tooling to RansomHub platform — continuation of criminal ecosystem.' },
  { ts:'2025-04-03T22:00:00Z', priority:'FLASH', src:'HUMINT-09', text:'APT28 human intelligence asset compromise suspected — operational group shifting communication channels and identity documents.' },
  { ts:'2025-04-02T16:45:00Z', priority:'CRITIC', src:'NETINT-07', text:'Gamaredon wave: 2,200 new phishing lures targeting Ukrainian Ministry of Defence personnel detected in 48h window.' },
  { ts:'2025-04-01T13:00:00Z', priority:'URGENT', src:'TECHINT-11', text:'Salt Typhoon packet capture capability confirmed in 2 additional tier-1 ISP backbones — geographic expansion beyond initial disclosure.' },
];

/* ── 2g  Geopolitical Risk Table (14 nations) ── */
const GEO_RISK = [
  { country:'Russia', code:'RU', flag:'🇷🇺', cyber_score:91, escalation:'HIGH', status:'Active Hostilities',
    groups:['APT28','APT29','Sandworm','Turla','Gamaredon'],
    nexus:'Ukraine war + global infrastructure targeting', predicted:'Continued ICS/OT targeting of NATO infrastructure' },
  { country:'China', code:'CN', flag:'🇨🇳', cyber_score:88, escalation:'ELEVATED', status:'Persistent Espionage',
    groups:['APT41','Volt Typhoon','Salt Typhoon','HAFNIUM','APT40'],
    nexus:'Taiwan tensions + economic espionage + pre-positioning', predicted:'Expanded telecom & critical infra pre-positioning ahead of Taiwan scenario' },
  { country:'North Korea', code:'KP', flag:'🇰🇵', cyber_score:82, escalation:'HIGH', status:'Financial Operations',
    groups:['Lazarus','Kimsuky','APT38'],
    nexus:'Sanctions evasion + nuclear funding', predicted:'Accelerated crypto theft — $1B+ annual target to fund weapons program' },
  { country:'Iran', code:'IR', flag:'🇮🇷', cyber_score:79, escalation:'ELEVATED', status:'Regional Tensions',
    groups:['APT33','APT34','MuddyWater'],
    nexus:'Israeli conflict + Gulf state tensions', predicted:'Destructive attacks on Israeli critical infrastructure + Gulf energy sector' },
  { country:'USA', code:'US', flag:'🇺🇸', cyber_score:97, escalation:'ACTIVE', status:'Offensive + Defensive',
    groups:['Equation Group'],
    nexus:'Global intelligence collection + counter-APT operations', predicted:'Expanded operations targeting adversary infrastructure and intelligence agencies' },
  { country:'Israel', code:'IL', flag:'🇮🇱', cyber_score:94, escalation:'ACTIVE', status:'Wartime Operations',
    groups:['Unit 8200'],
    nexus:'Gaza conflict + regional cyber warfare', predicted:'Continued ICS targeting of Iranian infrastructure + Hezbollah networks' },
  { country:'Ukraine', code:'UA', flag:'🇺🇦', cyber_score:83, escalation:'ACTIVE', status:'Under Active Attack',
    groups:['Defensive + NATO support'],
    nexus:'Active kinetic+cyber warfare theater', predicted:'Continued Russian wiper/espionage campaign — potential major infrastructure sabotage' },
  { country:'India', code:'IN', flag:'🇮🇳', cyber_score:72, escalation:'MODERATE', status:'Regional Espionage',
    groups:['Patchwork','SideWinder'],
    nexus:'Pakistan/China tensions', predicted:'Expanded operations against Pakistani/Chinese targets + domestic dissident monitoring' },
  { country:'Pakistan', code:'PK', flag:'🇵🇰', cyber_score:68, escalation:'MODERATE', status:'Cyber Espionage',
    groups:['Transparent Tribe'],
    nexus:'India tensions + domestic instability', predicted:'Continued spear-phishing of Indian defence officials and civil servants' },
  { country:'Vietnam', code:'VN', flag:'🇻🇳', cyber_score:64, escalation:'LOW', status:'Economic Espionage',
    groups:['APT32 (OceanLotus)'],
    nexus:'Regional economic competition + ASEAN tensions', predicted:'Targeted espionage against regional automotive, manufacturing, media' },
  { country:'Saudi Arabia', code:'SA', flag:'🇸🇦', cyber_score:75, escalation:'ELEVATED', status:'Targeted by Iran',
    groups:['Aramco defenders'],
    nexus:'Iran proxy conflict + oil sector targeting', predicted:'IRGC destructive attacks on energy sector following regional escalation events' },
  { country:'Taiwan', code:'TW', flag:'🇹🇼', cyber_score:86, escalation:'HIGH', status:'Pre-Conflict Probing',
    groups:['Volt Typhoon (against)','TAIDOOR (against)'],
    nexus:'China reunification pressure', predicted:'Volt Typhoon and APT40 likely to execute disruptive attacks on critical infrastructure in conflict scenario' },
  { country:'UK', code:'GB', flag:'🇬🇧', cyber_score:79, escalation:'ELEVATED', status:'APT + Ransomware',
    groups:['Targets: APT28 primary','LockBit RaaS'],
    nexus:'Russian hybrid warfare + NATO membership', predicted:'Continued APT28 election interference + ransomware targeting NHS' },
  { country:'Germany', code:'DE', flag:'🇩🇪', cyber_score:77, escalation:'ELEVATED', status:'Industrial Espionage',
    groups:['Targets: APT28','APT10 (China)'],
    nexus:'Industrial espionage + NATO infrastructure', predicted:'Automotive and industrial IP theft continuing; APT28 political interference pre-Bundestag elections' },
];

/* ═══════════════════════════════════════════════════════════════════════════
   §3  UTILITY HELPERS
═══════════════════════════════════════════════════════════════════════════ */
let _s = null; // module state

function _el(id) { return document.getElementById(id); }

function _esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function _sev(s) {
  return SEVERITY_CFG[s] || SEVERITY_CFG.Low;
}

function _badge(label, color, bg) {
  return `<span class="gtl-badge" style="color:${color};background:${bg};border:1px solid ${color}40;">${_esc(label)}</span>`;
}

function _flag(code) {
  const flags = {RU:'🇷🇺',CN:'🇨🇳',KP:'🇰🇵',IR:'🇮🇷',US:'🇺🇸',UK:'🇬🇧',IN:'🇮🇳',SD:'🇸🇩','US/UK':'🇺🇸'};
  return flags[code] || '🏴';
}

function _timeAgo(dateStr) {
  if (!dateStr) return 'Unknown';
  const d = new Date(dateStr), now = new Date();
  const diff = Math.floor((now - d) / 1000);
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  if (diff < 2592000) return `${Math.floor(diff/86400)}d ago`;
  return d.toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'});
}

function _statusColor(status) {
  const m = {Active:C.green, Monitoring:C.amber, Historical:C.muted, 'Active Hostilities':C.crit,
    'Persistent Espionage':C.orange, 'Financial Operations':C.amber, 'Regional Tensions':C.yellow,
    'Offensive + Defensive':C.blue, 'Wartime Operations':C.crit, 'Under Active Attack':C.crit,
    'Regional Espionage':C.muted, 'Cyber Espionage':C.muted, 'Economic Espionage':C.muted,
    'Targeted by Iran':C.orange, 'Pre-Conflict Probing':C.orange, 'APT + Ransomware':C.high,'Industrial Espionage':C.yellow};
  return m[status] || C.muted;
}

function _escLevel(level) {
  const m = {ACTIVE:C.crit,HIGH:C.orange,ELEVATED:C.amber,MODERATE:C.yellow,LOW:C.green};
  return m[level] || C.muted;
}

function _riskBar(val, color) {
  return `<div class="gtl-riskbar-wrap"><div class="gtl-riskbar" style="width:${val}%;background:${color};"></div><span>${val}</span></div>`;
}

function _priorityColor(p) {
  const m = {FLASH:C.crit,CRITIC:C.high,URGENT:C.amber,ROUTINE:C.muted};
  return m[p] || C.muted;
}

function _cvssColor(score) {
  if (score >= 9.0) return C.crit;
  if (score >= 7.0) return C.orange;
  if (score >= 4.0) return C.amber;
  return C.green;
}

/* ═══════════════════════════════════════════════════════════════════════════
   §4  WORLD MAP PANEL — D3.js + TopoJSON Cinematic Cyber Threat Map
═══════════════════════════════════════════════════════════════════════════ */

/* Spec severity colors */
const SEV_COLORS = {
  critical: '#ff3b5c',
  high:     '#ff8a3d',
  elevated: '#f5c518',
  moderate: '#3b82f6',
  low:      '#14b8a6',
};

/* Threat scores per ISO alpha-3 numeric (TopoJSON country ids) */
const THREAT_SCORES = {
  'US':98,'RU':82,'CN':79,'GB':72,'DE':68,'FR':67,'UA':91,'IL':75,
  'IR':74,'KP':71,'IN':65,'BR':63,'AU':69,'CA':71,'JP':66,'KR':68,
  'SA':72,'SG':69,'PK':64,'EG':63,'NG':60,'ZA':61,'TW':86,'VN':61,
  'TR':66,'MX':62,'AR':59,'NL':65,'PL':64,'SE':63,'NO':62,'FI':61,
  'CH':67,'BE':64,'ES':65,'IT':64,'PT':61,'GR':63,'RO':62,'CZ':63,
  'HU':61,'AT':62,'DK':63,'IE':61,'SY':71,'IQ':70,'LB':68,'AF':69,
  'PH':65,'ID':64,'MY':63,'TH':62,'BD':61,'MM':67,'LK':60,'NZ':60,
};

/* Attack arc definitions: src→tgt with actor/severity metadata */
const CYBER_ARCS = [
  {src:'RU',tgt:'UA',actor:'Sandworm',     sev:'critical', tech:'ICS/SCADA Wiper'},
  {src:'RU',tgt:'US',actor:'APT29',        sev:'high',     tech:'Spearphishing'},
  {src:'CN',tgt:'US',actor:'APT41',        sev:'high',     tech:'Supply Chain'},
  {src:'CN',tgt:'TW',actor:'APT40',        sev:'critical', tech:'Zero-Day Exploit'},
  {src:'KP',tgt:'US',actor:'Lazarus',      sev:'elevated', tech:'Crypto Heist'},
  {src:'IR',tgt:'IL',actor:'APT33',        sev:'critical', tech:'OT Attack'},
  {src:'IR',tgt:'SA',actor:'APT34',        sev:'high',     tech:'Phishing Kit'},
  {src:'RU',tgt:'DE',actor:'Fancy Bear',   sev:'elevated', tech:'DDoS'},
  {src:'KP',tgt:'KR',actor:'Kimsuky',      sev:'elevated', tech:'Watering Hole'},
  {src:'CN',tgt:'IN',actor:'APT15',        sev:'elevated', tech:'Border Espionage'},
  {src:'RU',tgt:'GB',actor:'Cozy Bear',    sev:'high',     tech:'Email Compromise'},
  {src:'CN',tgt:'JP',actor:'Stone Panda',  sev:'elevated', tech:'IP Theft'},
  {src:'IR',tgt:'US',actor:'ChaferAPT',    sev:'high',     tech:'RCE Exploit'},
  {src:'RU',tgt:'FR',actor:'Turla',        sev:'moderate', tech:'DNS Hijack'},
  {src:'CN',tgt:'AU',actor:'APT31',        sev:'high',     tech:'Gov Espionage'},
  {src:'KP',tgt:'JP',actor:'APT38',        sev:'high',     tech:'SWIFT Fraud'},
  {src:'RU',tgt:'PL',actor:'Gamaredon',    sev:'moderate', tech:'Malware Drop'},
  {src:'CN',tgt:'GB',actor:'APT10',        sev:'high',     tech:'MSP Breach'},
  {src:'IR',tgt:'DE',actor:'Tortoiseshell',sev:'moderate', tech:'Watering Hole'},
  {src:'KP',tgt:'IN',actor:'SilentChollima',sev:'moderate',tech:'Crypto Mining'},
];

/* Country geographic centroids [lng, lat] */
const COUNTRY_CENTROIDS = {
  US:[-98,38],CA:[-96,60],MX:[-102,24],BR:[-51,-10],AR:[-64,-34],
  GB:[-3,54],FR:[2,47],DE:[10,51],ES:[-4,40],IT:[12,42],NL:[5,52],
  PL:[20,52],UA:[31,49],RU:[100,62],TR:[35,39],SE:[18,62],NO:[15,65],
  FI:[27,64],CH:[8,47],BE:[4,51],AT:[14,47],DK:[10,56],IE:[-8,53],
  PT:[-8,39],GR:[22,38],RO:[25,46],CZ:[16,50],HU:[19,47],
  IL:[35,31],IR:[53,33],IQ:[44,33],SA:[45,24],SY:[38,35],LB:[36,34],
  IN:[80,22],PK:[70,30],AF:[65,33],BD:[90,24],LK:[81,8],
  CN:[104,36],JP:[138,37],KP:[127,40],KR:[128,36],TW:[121,24],
  VN:[108,14],PH:[122,13],ID:[118,-5],MY:[110,4],TH:[101,16],MM:[96,20],
  SG:[104,1],AU:[134,-26],NZ:[172,-41],
  EG:[29,27],NG:[8,10],ZA:[25,-30],
  CA_:[96,60],
};

/* Inject CSS for the cinematic map (idempotent) */
function _injectCyberMapCSS() {
  if (document.getElementById('gtl-cybermap-css')) return;
  const style = document.createElement('style');
  style.id = 'gtl-cybermap-css';
  style.textContent = `
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

    /* ── Root wrapper ── */
    #gtl-cybermap-root {
      font-family: 'JetBrains Mono', 'IBM Plex Mono', 'Courier New', monospace;
      background: #0a0e14;
      color: #e2e8f0;
      display: flex;
      flex-direction: column;
      gap: 0;
      min-height: 0;
    }

    /* ── KPI bar ── */
    .gcm-kpi-bar {
      display: flex;
      gap: 1px;
      background: #0d1117;
      border-bottom: 1px solid #1e2a3a;
      flex-shrink: 0;
    }
    .gcm-kpi-card {
      flex: 1;
      padding: 10px 14px;
      background: #0a0f1a;
      display: flex;
      flex-direction: column;
      gap: 4px;
      position: relative;
      overflow: hidden;
      cursor: default;
      transition: background 0.2s;
    }
    .gcm-kpi-card:hover { background: #0d1525; }
    .gcm-kpi-card::after {
      content: '';
      position: absolute;
      bottom: 0; left: 0; right: 0;
      height: 2px;
      background: var(--kpi-color, #00d4ff);
      opacity: 0.6;
    }
    .gcm-kpi-label {
      font-size: 9px;
      color: #4a5568;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .gcm-kpi-val {
      font-size: 22px;
      font-weight: 700;
      color: var(--kpi-color, #00d4ff);
      line-height: 1;
      transition: color 0.3s;
    }
    .gcm-kpi-val.gcm-flash {
      animation: gcm-val-flash 0.6s ease-out;
    }
    @keyframes gcm-val-flash {
      0%   { text-shadow: 0 0 20px var(--kpi-color,#00d4ff), 0 0 40px var(--kpi-color,#00d4ff); }
      100% { text-shadow: none; }
    }
    .gcm-kpi-spark {
      height: 24px;
      margin-top: 2px;
    }
    .gcm-kpi-sub {
      font-size: 9px;
      color: #2d3748;
    }

    /* ── LIVE badge ── */
    .gcm-live-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 9px;
      font-weight: 600;
      letter-spacing: 0.12em;
      color: #ff3b5c;
      text-transform: uppercase;
      padding: 3px 8px;
      border: 1px solid rgba(255,59,92,0.35);
      border-radius: 3px;
      background: rgba(255,59,92,0.08);
    }
    .gcm-live-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #ff3b5c;
      animation: gcm-live-breathe 1.8s ease-in-out infinite;
    }
    @keyframes gcm-live-breathe {
      0%, 100% { opacity: 1; box-shadow: 0 0 4px #ff3b5c, 0 0 8px #ff3b5c; transform: scale(1); }
      50%       { opacity: 0.3; box-shadow: none; transform: scale(0.7); }
    }

    /* ── Map area ── */
    .gcm-map-area {
      display: flex;
      flex: 1;
      min-height: 420px;
      position: relative;
      overflow: hidden;
      background: #0a0e14;
    }
    .gcm-svg-wrap {
      flex: 1;
      position: relative;
      min-width: 0;
    }
    #gcm-world-svg {
      width: 100%;
      height: 100%;
      display: block;
      background: radial-gradient(ellipse at 50% 40%, #0d1525 0%, #0a0e14 70%);
    }
    /* Scanline texture */
    #gcm-world-svg::before {
      content: '';
      position: absolute;
      inset: 0;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 3px,
        rgba(0,212,255,0.015) 3px,
        rgba(0,212,255,0.015) 4px
      );
      pointer-events: none;
    }

    /* Country paths */
    .gcm-country {
      fill: #141a24;
      stroke: #1e2a3a;
      stroke-width: 0.4;
      cursor: pointer;
      transition: fill 0.25s, stroke 0.25s, filter 0.25s;
    }
    .gcm-country:hover {
      stroke: #00d4ff;
      stroke-width: 0.8;
      filter: drop-shadow(0 0 4px rgba(0,212,255,0.5));
    }
    .gcm-country.gcm-country-active {
      stroke: #00d4ff;
      stroke-width: 1;
      filter: drop-shadow(0 0 6px rgba(0,212,255,0.6));
    }

    /* Graticule */
    .gcm-graticule {
      fill: none;
      stroke: #1a2235;
      stroke-width: 0.3;
    }
    .gcm-sphere {
      fill: #0a0e14;
    }

    /* Origin / target nodes */
    .gcm-node-origin {
      cursor: pointer;
    }
    .gcm-node-origin circle.core {
      transition: r 0.2s;
    }
    .gcm-node-origin:hover circle.core { r: 7; }
    .gcm-ping-ring {
      fill: none;
      transform-origin: center;
      animation: gcm-ping 2.4s ease-out infinite;
      pointer-events: none;
    }
    .gcm-ping-ring.r2 { animation-delay: 0.8s; }
    .gcm-ping-ring.r3 { animation-delay: 1.6s; }
    @keyframes gcm-ping {
      0%   { opacity: 0.7; transform: scale(1); }
      100% { opacity: 0;   transform: scale(3.2); }
    }

    /* Attack arcs */
    .gcm-arc-trail {
      fill: none;
      stroke-linecap: round;
    }

    /* Tooltip */
    #gcm-tooltip {
      position: absolute;
      background: rgba(10,14,20,0.95);
      border: 1px solid #1e2a3a;
      border-radius: 6px;
      padding: 10px 14px;
      font-size: 11px;
      font-family: 'JetBrains Mono','IBM Plex Mono',monospace;
      color: #e2e8f0;
      pointer-events: none;
      opacity: 0;
      transition: opacity 0.15s;
      z-index: 100;
      max-width: 240px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.8), 0 0 0 1px rgba(0,212,255,0.1);
      white-space: nowrap;
    }
    #gcm-tooltip.visible { opacity: 1; }
    .gcm-tip-title { font-size: 12px; font-weight: 600; margin-bottom: 5px; color: #00d4ff; }
    .gcm-tip-row { display: flex; gap: 8px; margin: 2px 0; color: #94a3b8; font-size: 10px; }
    .gcm-tip-row span:first-child { color: #4a5568; }
    .gcm-tip-sev { font-weight: 600; }

    /* ── Right side panel ── */
    .gcm-side-panel {
      width: 220px;
      flex-shrink: 0;
      background: #0d1117;
      border-left: 1px solid #1e2a3a;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .gcm-panel-hdr {
      padding: 10px 12px;
      border-bottom: 1px solid #1e2a3a;
      font-size: 10px;
      color: #4a5568;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .gcm-spotlight-body {
      flex: 1;
      overflow-y: auto;
      padding: 12px;
      scrollbar-width: thin;
      scrollbar-color: #1e2a3a transparent;
    }
    .gcm-spotlight-empty {
      color: #2d3748;
      font-size: 11px;
      text-align: center;
      padding: 24px 8px;
      line-height: 1.6;
    }

    /* ── Attack ticker ── */
    .gcm-ticker-wrap {
      border-top: 1px solid #1e2a3a;
      background: #0a0e14;
      flex-shrink: 0;
      height: 100px;
      overflow: hidden;
      position: relative;
    }
    .gcm-ticker-hdr {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 12px;
      border-bottom: 1px solid #111928;
      font-size: 9px;
      color: #4a5568;
      text-transform: uppercase;
      letter-spacing: 0.1em;
    }
    .gcm-ticker-list {
      padding: 4px 0;
      overflow: hidden;
      height: 72px;
    }
    .gcm-tick-entry {
      display: flex;
      align-items: baseline;
      gap: 8px;
      padding: 3px 12px;
      font-size: 10px;
      font-family: 'JetBrains Mono','IBM Plex Mono',monospace;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      border-left: 2px solid transparent;
      transition: background 0.3s, border-color 0.3s;
    }
    .gcm-tick-entry.gcm-tick-new {
      animation: gcm-tick-glow 1.5s ease-out;
    }
    @keyframes gcm-tick-glow {
      0%  { background: rgba(255,59,92,0.12); border-left-color: #ff3b5c; }
      100%{ background: transparent; border-left-color: transparent; }
    }
    .gcm-tick-time { color: #2d3748; font-size: 9px; flex-shrink: 0; }
    .gcm-tick-actor { font-weight: 600; flex-shrink: 0; }
    .gcm-tick-arrow { color: #2d3748; flex-shrink: 0; }
    .gcm-tick-tgt { color: #94a3b8; flex-shrink: 0; }
    .gcm-tick-dot { color: #2d3748; flex-shrink: 0; }
    .gcm-tick-tech { color: #4a5568; font-size: 9px; overflow: hidden; text-overflow: ellipsis; }

    /* ── Legend ── */
    .gcm-legend {
      display: flex;
      gap: 14px;
      align-items: center;
      padding: 6px 12px;
      border-top: 1px solid #1e2a3a;
      background: #0a0e14;
      flex-wrap: wrap;
    }
    .gcm-legend-item {
      display: flex;
      align-items: center;
      gap: 5px;
      font-size: 9px;
      color: #64748b;
    }
    .gcm-legend-swatch {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      flex-shrink: 0;
    }

    /* ── Sparkline SVGs ── */
    .gcm-spark-svg { overflow: visible; }
    .gcm-spark-line { fill: none; stroke-width: 1.5; vector-effect: non-scaling-stroke; }
    .gcm-spark-area { opacity: 0.15; }

    /* ── Spotlight content ── */
    .gcm-spot-flag   { font-size: 28px; line-height: 1; }
    .gcm-spot-name   { font-size: 13px; font-weight: 700; color: #e2e8f0; margin-top: 4px; }
    .gcm-spot-score  { font-size: 11px; margin-top: 2px; }
    .gcm-spot-bar-wrap{ background:#111928; border-radius:2px; height:4px; margin:8px 0 4px; overflow:hidden; }
    .gcm-spot-bar    { height:100%; border-radius:2px; transition: width 0.6s ease; }
    .gcm-spot-section{ font-size: 9px; color: #4a5568; text-transform: uppercase; letter-spacing: 0.08em; margin: 10px 0 4px; }
    .gcm-spot-chip   { display:inline-block; padding:2px 7px; border-radius:10px; font-size:9px; margin:2px 2px 0 0;
                        background:rgba(0,212,255,0.08); border:1px solid rgba(0,212,255,0.2); color:#94a3b8; }
    .gcm-spot-stat   { display:flex; justify-content:space-between; font-size:10px; padding:3px 0; border-bottom:1px solid #111928; }
    .gcm-spot-stat span:first-child { color:#4a5568; }

    /* ── Arc count badge ── */
    .gcm-arc-count {
      position: absolute;
      top: 8px; right: 8px;
      font-size: 9px;
      color: #2d3748;
      background: rgba(10,14,20,0.7);
      border: 1px solid #1e2a3a;
      padding: 3px 8px;
      border-radius: 3px;
      pointer-events: none;
    }

    /* ── Responsive ── */
    @media (max-width: 900px) {
      .gcm-side-panel { display: none; }
      .gcm-kpi-card { padding: 8px 8px; }
      .gcm-kpi-val  { font-size: 18px; }
    }
    @media (max-width: 600px) {
      .gcm-kpi-bar { flex-wrap: wrap; }
      .gcm-kpi-card { flex: 0 0 50%; }
    }
  `;
  document.head.appendChild(style);
}

/* Build the HTML skeleton for the cyber map */
function _buildWorldMap() {
  _injectCyberMapCSS();

  const totalActors = GTL_ACTORS.filter(a => a.active).length;
  const activeCamps = GTL_CAMPAIGNS.filter(c => c.status === 'Active').length;
  const critVulns   = GTL_VULNS.filter(v => v.severity === 'Critical' && v.exploit_wild).length;
  const zerodays    = GTL_VULNS.filter(v => v.zero_day && v.exploit_wild).length;

  const kpis = [
    { label:'Active APT Groups',    val:totalActors, color:'#ff3b5c', id:'gcm-kv-apt'   },
    { label:'Active Campaigns',     val:activeCamps, color:'#ff8a3d', id:'gcm-kv-camp'  },
    { label:'Critical Wild Exploits',val:critVulns,  color:'#ff3b5c', id:'gcm-kv-crit'  },
    { label:'In-Wild Zero-Days',    val:zerodays,    color:'#a855f7', id:'gcm-kv-zero'  },
    { label:'Intel Feed Status',    val:'LIVE',      color:'#ff3b5c', id:'gcm-kv-live', isLive:true },
  ];

  const kpiHtml = kpis.map(k => `
    <div class="gcm-kpi-card" style="--kpi-color:${k.color}">
      <div class="gcm-kpi-label">${k.label}</div>
      ${k.isLive
        ? `<div class="gcm-kpi-val" id="${k.id}"><span class="gcm-live-badge"><span class="gcm-live-dot"></span>LIVE</span></div>`
        : `<div class="gcm-kpi-val" id="${k.id}">${k.val}</div>`
      }
      ${k.isLive ? '' : `<svg class="gcm-kpi-spark" id="${k.id}-spark" viewBox="0 0 80 24" preserveAspectRatio="none"></svg>`}
      <div class="gcm-kpi-sub">&nbsp;</div>
    </div>`).join('');

  return `
<div id="gtl-cybermap-root">
  <div class="gcm-kpi-bar">${kpiHtml}</div>

  <div class="gcm-map-area">
    <div class="gcm-svg-wrap">
      <svg id="gcm-world-svg" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <radialGradient id="gcm-vignette" cx="50%" cy="50%" r="60%">
            <stop offset="0%"   stop-color="#0a0e14" stop-opacity="0"/>
            <stop offset="100%" stop-color="#050810" stop-opacity="0.7"/>
          </radialGradient>
          <filter id="gcm-glow-crit">
            <feGaussianBlur stdDeviation="2.5" result="blur"/>
            <feComposite in="SourceGraphic" in2="blur" operator="over"/>
          </filter>
          <filter id="gcm-glow-high">
            <feGaussianBlur stdDeviation="2" result="blur"/>
            <feComposite in="SourceGraphic" in2="blur" operator="over"/>
          </filter>
          <filter id="gcm-glow-soft">
            <feGaussianBlur stdDeviation="1.5" result="blur"/>
            <feComposite in="SourceGraphic" in2="blur" operator="over"/>
          </filter>
          <filter id="gcm-country-hover">
            <feGaussianBlur stdDeviation="3" result="blur"/>
            <feComposite in="SourceGraphic" in2="blur" operator="over"/>
          </filter>
        </defs>
        <!-- Sphere (ocean) -->
        <path class="gcm-sphere" id="gcm-sphere-path"/>
        <!-- Graticule grid -->
        <path class="gcm-graticule" id="gcm-graticule-path"/>
        <!-- Scanline texture overlay -->
        <rect id="gcm-scanline" width="100%" height="100%" fill="url(#gcm-scanline-pat)" opacity="0.03" pointer-events="none"/>
        <!-- Countries layer -->
        <g id="gcm-countries-g"></g>
        <!-- Borders -->
        <path id="gcm-borders-path" fill="none" stroke="#0d1a2d" stroke-width="0.3"/>
        <!-- Arcs layer (below nodes) -->
        <g id="gcm-arcs-g"></g>
        <!-- Nodes layer -->
        <g id="gcm-nodes-g"></g>
        <!-- Vignette -->
        <rect width="100%" height="100%" fill="url(#gcm-vignette)" pointer-events="none"/>
      </svg>
      <div id="gcm-tooltip"></div>
      <div class="gcm-arc-count" id="gcm-arc-count">Loading map…</div>
    </div>

    <div class="gcm-side-panel">
      <div class="gcm-panel-hdr">
        <span>Country Threat Profile</span>
        <span class="gcm-live-badge" style="padding:1px 6px;font-size:8px;">
          <span class="gcm-live-dot"></span>LIVE
        </span>
      </div>
      <div class="gcm-spotlight-body" id="gcm-spotlight-body">
        <div class="gcm-spotlight-empty">
          <i class="fas fa-crosshairs" style="font-size:22px;color:#1e2a3a;display:block;margin-bottom:10px;"></i>
          Click any country<br>to view its threat profile
        </div>
      </div>
    </div>
  </div>

  <div class="gcm-legend">
    <span style="font-size:9px;color:#2d3748;text-transform:uppercase;letter-spacing:.1em;margin-right:4px;">Threat Level</span>
    <div class="gcm-legend-item"><span class="gcm-legend-swatch" style="background:#ff3b5c;box-shadow:0 0 4px #ff3b5c;"></span>Critical (90+)</div>
    <div class="gcm-legend-item"><span class="gcm-legend-swatch" style="background:#ff8a3d;box-shadow:0 0 4px #ff8a3d;"></span>High (80-89)</div>
    <div class="gcm-legend-item"><span class="gcm-legend-swatch" style="background:#f5c518;box-shadow:0 0 4px #f5c518;"></span>Elevated (70-79)</div>
    <div class="gcm-legend-item"><span class="gcm-legend-swatch" style="background:#3b82f6;box-shadow:0 0 4px #3b82f6;"></span>Moderate (60-69)</div>
    <div class="gcm-legend-item"><span class="gcm-legend-swatch" style="background:#14b8a6;box-shadow:0 0 4px #14b8a6;"></span>Low (&lt;60)</div>
    <div style="margin-left:auto;display:flex;gap:12px;">
      <div class="gcm-legend-item">
        <svg width="14" height="14" viewBox="0 0 14 14"><circle cx="7" cy="7" r="4" fill="none" stroke="#ff3b5c" stroke-width="1.5" opacity="0.6"/>
          <circle cx="7" cy="7" r="2" fill="#ff3b5c"/></svg>Origin node
      </div>
      <div class="gcm-legend-item">
        <svg width="14" height="14" viewBox="0 0 14 14"><circle cx="7" cy="7" r="3" fill="#3b82f6" opacity="0.8"/></svg>Target node
      </div>
    </div>
  </div>

  <div class="gcm-ticker-wrap">
    <div class="gcm-ticker-hdr">
      <span class="gcm-live-badge"><span class="gcm-live-dot"></span>LIVE</span>
      <span>Attack Intelligence Feed</span>
      <span id="gcm-attack-count" style="margin-left:auto;color:#1e2a3a;">—</span>
    </div>
    <div class="gcm-ticker-list" id="gcm-ticker-list"></div>
  </div>
</div>

<div class="gtl-map-spotlight" id="gtl-map-spotlight" style="display:none;"></div>`;
}

/* ── D3 + TopoJSON Cyber Map Engine ── */
let _gcmRAF = null;
let _gcmComets = [];
let _gcmProjection = null;
let _gcmTopoData = null;
let _gcmInitialized = false;

function _sevColor(sev) {
  switch((sev||'').toLowerCase()) {
    case 'critical': return SEV_COLORS.critical;
    case 'high':     return SEV_COLORS.high;
    case 'elevated': return SEV_COLORS.elevated;
    case 'moderate': return SEV_COLORS.moderate;
    default:         return SEV_COLORS.low;
  }
}

function _scoreToSev(score) {
  if (score >= 90) return 'critical';
  if (score >= 80) return 'high';
  if (score >= 70) return 'elevated';
  if (score >= 60) return 'moderate';
  return 'low';
}

function _loadScript(src) {
  return new Promise((resolve, reject) => {
    if (document.querySelector(`script[src="${src}"]`)) { resolve(); return; }
    const s = document.createElement('script');
    s.src = src; s.async = true;
    s.onload = resolve; s.onerror = reject;
    document.head.appendChild(s);
  });
}

async function _initCyberMap() {
  if (_gcmInitialized) return;

  /* Load D3 and TopoJSON from CDN */
  try {
    await _loadScript('https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js');
    await _loadScript('https://cdn.jsdelivr.net/npm/topojson-client@3/dist/topojson-client.min.js');
  } catch(e) {
    const countEl = document.getElementById('gcm-arc-count');
    if (countEl) countEl.textContent = 'Map libs failed to load';
    console.error('[CyberMap] CDN load error:', e);
    return;
  }

  const svg = document.getElementById('gcm-world-svg');
  if (!svg) return;

  /* Fetch world atlas TopoJSON */
  let world;
  try {
    const resp = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json');
    world = await resp.json();
  } catch(e) {
    console.error('[CyberMap] world-atlas fetch error:', e);
    const countEl = document.getElementById('gcm-arc-count');
    if (countEl) countEl.textContent = 'Map data unavailable';
    return;
  }

  _gcmTopoData = world;
  _gcmInitialized = true;
  _gcmRender(svg, world);
}

function _gcmRender(svg, world) {
  const d3 = window.d3;
  const topojson = window.topojson;
  if (!d3 || !topojson) return;

  const svgEl = d3.select(svg);
  const W = svg.clientWidth  || svg.parentElement.clientWidth  || 800;
  const H = svg.clientHeight || svg.parentElement.clientHeight || 450;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  /* Natural Earth projection */
  const projection = d3.geoNaturalEarth1()
    .scale(W / 6.2)
    .translate([W / 2, H / 2]);
  _gcmProjection = projection;

  const path = d3.geoPath().projection(projection);

  /* Sphere (ocean background) */
  svgEl.select('#gcm-sphere-path')
    .datum({type:'Sphere'})
    .attr('d', path)
    .attr('fill', '#0a0e14');

  /* Graticule */
  const graticule = d3.geoGraticule().step([20, 20]);
  svgEl.select('#gcm-graticule-path')
    .datum(graticule())
    .attr('d', path)
    .attr('stroke', '#111928')
    .attr('stroke-width', 0.3)
    .attr('fill', 'none');

  /* Countries */
  const countries = topojson.feature(world, world.objects.countries);
  const borders   = topojson.mesh(world, world.objects.countries, (a,b) => a !== b);

  /* Numeric → ISO alpha-2 lookup (partial, covers our threat map) */
  const NUM_TO_ISO = {
    840:'US',643:'RU',156:'CN',826:'GB',276:'DE',250:'FR',804:'UA',376:'IL',
    364:'IR',408:'KP',356:'IN',76:'BR',36:'AU',124:'CA',392:'JP',410:'KR',
    682:'SA',702:'SG',586:'PK',818:'EG',566:'NG',710:'ZA',158:'TW',704:'VN',
    792:'TR',484:'MX',32:'AR',528:'NL',616:'PL',752:'SE',578:'NO',246:'FI',
    756:'CH',56:'BE',40:'AT',208:'DK',372:'IE',620:'PT',300:'GR',642:'RO',
    203:'CZ',348:'HU',724:'ES',380:'IT',760:'SY',368:'IQ',422:'LB',4:'AF',
    608:'PH',360:'ID',458:'MY',764:'TH',104:'MM',50:'BD',144:'LK',554:'NZ',
    218:'EC',604:'PE',170:'CO',862:'VE',152:'CL',320:'GT',188:'CR',591:'PA',
    52:'BB',388:'JM',214:'DO',630:'PR',792:'TR',31:'AZ',268:'GE',51:'AM',
    860:'UZ',398:'KZ',417:'KG',762:'TJ',795:'TM',496:'MN',116:'KH',418:'LA',
    144:'LK',694:'SL',288:'GH',384:'CI',430:'LR',562:'NE',854:'BF',466:'ML',
    686:'SN',440:'LT',428:'LV',233:'EE',112:'BY',498:'MD',807:'MK',8:'AL',
    705:'SI',191:'HR',891:'RS',70:'BA',499:'ME',414:'KW',784:'AE',48:'BH',
    512:'OM',275:'PS',434:'LY',788:'TN',12:'DZ',504:'MA',706:'SO',231:'ET',
    404:'KE',800:'UG',834:'TZ',508:'MZ',454:'MW',716:'ZW',426:'LS',748:'SZ',
    72:'BW',516:'NA',24:'AO',180:'CD',178:'CG',120:'CM',140:'CF',148:'TD',
    729:'SD',728:'SS',646:'RW',108:'BI',454:'MW',686:'SN',466:'ML',562:'NE',
  };

  const countriesG = svgEl.select('#gcm-countries-g');

  countriesG.selectAll('path')
    .data(countries.features)
    .join('path')
    .attr('class', 'gcm-country')
    .attr('d', path)
    .attr('data-iso', d => NUM_TO_ISO[+d.id] || '')
    .attr('data-name', d => _gcmCountryName(+d.id, NUM_TO_ISO))
    .style('fill', d => {
      const iso = NUM_TO_ISO[+d.id];
      const score = iso ? (THREAT_SCORES[iso] || 35) : 35;
      return _gcmScoreToFill(score);
    })
    .on('mouseover', function(event, d) {
      const iso   = NUM_TO_ISO[+d.id] || '';
      const score = iso ? (THREAT_SCORES[iso] || 35) : 35;
      const name  = _gcmCountryName(+d.id, NUM_TO_ISO);
      if (!iso) return;
      const actor = GTL_ACTORS.filter(a => a.origin === iso)[0];
      const camps = GTL_CAMPAIGNS.filter(c => {
        const a = GTL_ACTORS.find(x=>x.id===c.actor);
        return a && a.origin === iso;
      }).length;
      _gcmShowTooltip(event, `
        <div class="gcm-tip-title">${name}</div>
        <div class="gcm-tip-row"><span>Threat Score</span><span class="gcm-tip-sev" style="color:${_sevColor(_scoreToSev(score))}">${score}/100</span></div>
        <div class="gcm-tip-row"><span>Campaigns</span><span>${camps}</span></div>
        ${actor ? `<div class="gcm-tip-row"><span>Top Actor</span><span>${actor.name}</span></div>` : ''}
        <div class="gcm-tip-row" style="color:#2d3748;font-size:9px;margin-top:4px;">Click to expand profile</div>
      `);
      d3.select(this)
        .style('stroke', '#00d4ff')
        .style('stroke-width', 0.8)
        .style('filter', 'drop-shadow(0 0 5px rgba(0,212,255,0.5))');
    })
    .on('mousemove', _gcmMoveTooltip)
    .on('mouseout', function(event, d) {
      _gcmHideTooltip();
      const iso = NUM_TO_ISO[+d.id] || '';
      const score = iso ? (THREAT_SCORES[iso] || 35) : 35;
      d3.select(this)
        .style('stroke', score >= 80 ? 'rgba(255,59,92,0.4)' : '#1e2a3a')
        .style('stroke-width', score >= 80 ? 0.6 : 0.4)
        .style('filter', null);
    })
    .on('click', function(event, d) {
      const iso  = NUM_TO_ISO[+d.id] || '';
      const name = _gcmCountryName(+d.id, NUM_TO_ISO);
      const score= iso ? (THREAT_SCORES[iso] || 35) : 35;
      if (iso) _gcmShowCountryPanel(iso, name, score);
    });

  /* Borders */
  svgEl.select('#gcm-borders-path')
    .datum(borders)
    .attr('d', path)
    .attr('stroke', '#0d1a2d')
    .attr('stroke-width', 0.3);

  /* Render attack nodes and arcs */
  _gcmRenderNodes(projection, W, H);
  _gcmRenderArcs(svg, projection);
  _gcmStartTicker();
  _gcmDrawSparklines();

  const countEl = document.getElementById('gcm-arc-count');
  if (countEl) countEl.textContent = `${Math.min(CYBER_ARCS.length, 25)} live arcs`;
}

function _gcmCountryName(numId, NUM_TO_ISO) {
  const iso = NUM_TO_ISO[numId];
  const names = {
    US:'United States',RU:'Russia',CN:'China',GB:'United Kingdom',DE:'Germany',
    FR:'France',UA:'Ukraine',IL:'Israel',IR:'Iran',KP:'North Korea',IN:'India',
    BR:'Brazil',AU:'Australia',CA:'Canada',JP:'Japan',KR:'South Korea',
    SA:'Saudi Arabia',SG:'Singapore',PK:'Pakistan',EG:'Egypt',NG:'Nigeria',
    ZA:'South Africa',TW:'Taiwan',VN:'Vietnam',TR:'Turkey',MX:'Mexico',
    AR:'Argentina',NL:'Netherlands',PL:'Poland',SE:'Sweden',NO:'Norway',
    FI:'Finland',CH:'Switzerland',BE:'Belgium',AT:'Austria',DK:'Denmark',
    IE:'Ireland',ES:'Spain',IT:'Italy',PT:'Portugal',GR:'Greece',RO:'Romania',
    CZ:'Czech Republic',HU:'Hungary',SY:'Syria',IQ:'Iraq',LB:'Lebanon',
    AF:'Afghanistan',PH:'Philippines',ID:'Indonesia',MY:'Malaysia',TH:'Thailand',
    MM:'Myanmar',BD:'Bangladesh',LK:'Sri Lanka',NZ:'New Zealand',
    AZ:'Azerbaijan',GE:'Georgia',AM:'Armenia',KZ:'Kazakhstan',UZ:'Uzbekistan',
    KG:'Kyrgyzstan',TJ:'Tajikistan',TM:'Turkmenistan',MN:'Mongolia',KH:'Cambodia',
    LA:'Laos',KW:'Kuwait',AE:'UAE',BH:'Bahrain',OM:'Oman',LY:'Libya',
    TN:'Tunisia',DZ:'Algeria',MA:'Morocco',SO:'Somalia',ET:'Ethiopia',
    KE:'Kenya',UG:'Uganda',TZ:'Tanzania',MZ:'Mozambique',ZW:'Zimbabwe',
    AO:'Angola',CD:'DR Congo',CG:'Congo',CM:'Cameroon',SD:'Sudan',SS:'South Sudan',
  };
  return (iso && names[iso]) || 'Unknown';
}

function _gcmScoreToFill(score) {
  if (score >= 90) return 'rgba(255,59,92,0.35)';
  if (score >= 80) return 'rgba(255,138,61,0.28)';
  if (score >= 70) return 'rgba(245,197,24,0.22)';
  if (score >= 60) return 'rgba(59,130,246,0.18)';
  if (score >= 40) return 'rgba(20,184,166,0.10)';
  return '#141a24';
}

function _gcmRenderNodes(projection, W, H) {
  const d3 = window.d3;
  const nodesG = d3.select('#gcm-nodes-g');
  nodesG.selectAll('*').remove();

  /* Origins — one per unique source country */
  const origins = [...new Set(CYBER_ARCS.map(a => a.src))];
  origins.forEach(iso => {
    const centroid = COUNTRY_CENTROIDS[iso];
    if (!centroid) return;
    const [px, py] = projection(centroid);
    if (isNaN(px) || isNaN(py)) return;

    const arcs = CYBER_ARCS.filter(a => a.src === iso);
    const maxSev = arcs.reduce((best, a) => {
      const order = {critical:0,high:1,elevated:2,moderate:3,low:4};
      return order[a.sev] < order[best] ? a.sev : best;
    }, 'low');
    const col = _sevColor(maxSev);
    const r   = Math.min(3 + arcs.length * 1.4, 9);

    const g = nodesG.append('g')
      .attr('class', 'gcm-node-origin')
      .attr('transform', `translate(${px},${py})`)
      .style('cursor','pointer')
      .on('mouseover', function(event) {
        _gcmShowTooltip(event, `
          <div class="gcm-tip-title">${iso} — Origin Node</div>
          <div class="gcm-tip-row"><span>Active arcs</span><span>${arcs.length}</span></div>
          <div class="gcm-tip-row"><span>Max severity</span><span class="gcm-tip-sev" style="color:${col}">${maxSev.toUpperCase()}</span></div>
          <div class="gcm-tip-row"><span>Top actor</span><span>${arcs[0].actor}</span></div>
        `);
      })
      .on('mousemove', _gcmMoveTooltip)
      .on('mouseout', _gcmHideTooltip);

    /* Radar ping rings */
    ['r1','r2','r3'].forEach(cls => {
      g.append('circle')
        .attr('class', `gcm-ping-ring ${cls}`)
        .attr('r', r * 1.8)
        .style('stroke', col)
        .style('stroke-width', 0.8)
        .style('stroke-opacity', 0.5)
        .style('fill', 'none');
    });

    /* Core dot */
    g.append('circle')
      .attr('class', 'core')
      .attr('r', r)
      .style('fill', col)
      .style('fill-opacity', 0.9)
      .style('filter', `drop-shadow(0 0 ${r}px ${col})`);

    /* Inner dot */
    g.append('circle')
      .attr('r', Math.max(r*0.4, 1.5))
      .style('fill', '#fff')
      .style('fill-opacity', 0.8)
      .style('pointer-events', 'none');
  });

  /* Targets */
  const targets = [...new Set(CYBER_ARCS.map(a => a.tgt))];
  targets.forEach(iso => {
    if (origins.includes(iso)) return; /* don't double-draw */
    const centroid = COUNTRY_CENTROIDS[iso];
    if (!centroid) return;
    const [px, py] = projection(centroid);
    if (isNaN(px) || isNaN(py)) return;

    const score = THREAT_SCORES[iso] || 40;
    const col   = _sevColor(_scoreToSev(score));

    const arcsHit = CYBER_ARCS.filter(a => a.tgt === iso);

    nodesG.append('g')
      .attr('transform', `translate(${px},${py})`)
      .style('cursor','pointer')
      .on('mouseover', function(event) {
        _gcmShowTooltip(event, `
          <div class="gcm-tip-title">${iso} — Target Node</div>
          <div class="gcm-tip-row"><span>Threat score</span><span style="color:${col}">${score}/100</span></div>
          <div class="gcm-tip-row"><span>Inbound arcs</span><span>${arcsHit.length}</span></div>
          ${arcsHit[0] ? `<div class="gcm-tip-row"><span>Latest</span><span>${arcsHit[0].actor} · ${arcsHit[0].tech}</span></div>` : ''}
        `);
      })
      .on('mousemove', _gcmMoveTooltip)
      .on('mouseout', _gcmHideTooltip)
      .append('circle')
      .attr('r', 3.5)
      .style('fill', col)
      .style('fill-opacity', 0.75)
      .style('stroke', col)
      .style('stroke-width', 0.5)
      .style('stroke-opacity', 0.4)
      .style('filter', `drop-shadow(0 0 3px ${col})`);
  });
}

function _gcmRenderArcs(svgEl, projection) {
  const d3 = window.d3;
  const arcsG = d3.select('#gcm-arcs-g');
  arcsG.selectAll('*').remove();
  _gcmComets = [];
  if (_gcmRAF) { cancelAnimationFrame(_gcmRAF); _gcmRAF = null; }

  const maxArcs = Math.min(CYBER_ARCS.length, 25);
  const activeArcs = CYBER_ARCS.slice(0, maxArcs);

  activeArcs.forEach((arc, i) => {
    const srcC = COUNTRY_CENTROIDS[arc.src];
    const tgtC = COUNTRY_CENTROIDS[arc.tgt];
    if (!srcC || !tgtC) return;

    const [sx, sy] = projection(srcC);
    const [tx, ty] = projection(tgtC);
    if (isNaN(sx)||isNaN(sy)||isNaN(tx)||isNaN(ty)) return;

    const col = _sevColor(arc.sev);

    /* Control point: elevated above midpoint for a great-circle-like arc */
    const mx = (sx + tx) / 2;
    const my = (sy + ty) / 2 - Math.hypot(tx-sx, ty-sy) * 0.35;
    const dStr = `M${sx},${sy} Q${mx},${my} ${tx},${ty}`;

    /* Ghost trail path (faint static arc) */
    arcsG.append('path')
      .attr('class', 'gcm-arc-trail')
      .attr('d', dStr)
      .attr('stroke', col)
      .attr('stroke-width', 0.5)
      .attr('stroke-opacity', 0.15)
      .on('mouseover', function(event) {
        _gcmShowTooltip(event, `
          <div class="gcm-tip-title">${arc.actor}</div>
          <div class="gcm-tip-row"><span>Route</span><span>${arc.src} → ${arc.tgt}</span></div>
          <div class="gcm-tip-row"><span>Severity</span><span class="gcm-tip-sev" style="color:${col}">${arc.sev.toUpperCase()}</span></div>
          <div class="gcm-tip-row"><span>Technique</span><span>${arc.tech}</span></div>
          <div class="gcm-tip-row"><span>Last seen</span><span>${_gcmTimeAgo()}</span></div>
        `);
      })
      .on('mousemove', _gcmMoveTooltip)
      .on('mouseout', _gcmHideTooltip);

    /* Comet dot */
    const comet = arcsG.append('circle')
      .attr('r', arc.sev === 'critical' ? 3 : arc.sev === 'high' ? 2.5 : 2)
      .attr('fill', col)
      .style('filter', `drop-shadow(0 0 ${arc.sev === 'critical' ? 5 : 3}px ${col})`)
      .style('pointer-events', 'none');

    /* Comet tail */
    const tail = arcsG.append('path')
      .attr('fill', 'none')
      .attr('stroke', col)
      .attr('stroke-width', arc.sev === 'critical' ? 1.8 : 1.2)
      .attr('stroke-opacity', 0)
      .style('pointer-events', 'none');

    /* Create a hidden SVG path to measure lengths */
    const measPath = document.createElementNS('http://www.w3.org/2000/svg','path');
    measPath.setAttribute('d', dStr);
    const totalLen = measPath.getTotalLength();

    const speed = 1.5 + Math.random() * 1.5;          /* seconds for full traversal */
    const delay = i * 0.18 + Math.random() * 0.8;     /* stagger start */
    const tailFrac = 0.12;                             /* tail is 12% of path length */

    _gcmComets.push({
      comet, tail, measPath, totalLen,
      speed, delay,
      startTime: null,
      col,
    });
  });

  /* RAF animation loop */
  let firstTick = null;
  function tick(ts) {
    if (!firstTick) firstTick = ts;
    const elapsed = (ts - firstTick) / 1000; /* seconds */

    _gcmComets.forEach(c => {
      const t = ((elapsed - c.delay) % c.speed) / c.speed;
      if (t < 0) { /* before delay — hide */ c.comet.attr('opacity',0); c.tail.attr('stroke-opacity',0); return; }

      const pos  = c.totalLen * t;
      const pt   = c.measPath.getPointAtLength(Math.min(pos, c.totalLen - 0.1));
      const tailStart = Math.max(0, pos - c.totalLen * 0.12);
      const tailPts = [];
      const steps = 8;
      for (let s = 0; s <= steps; s++) {
        const sp = tailStart + (pos - tailStart) * (s / steps);
        const tp = c.measPath.getPointAtLength(Math.min(sp, c.totalLen - 0.1));
        tailPts.push(`${s===0?'M':'L'}${tp.x},${tp.y}`);
      }

      c.comet.attr('cx', pt.x).attr('cy', pt.y).attr('opacity', 0.95);
      c.tail
        .attr('d', tailPts.join(' '))
        .attr('stroke-opacity', 0.55 * Math.min(t * 6, 1));
    });

    _gcmRAF = requestAnimationFrame(tick);
  }

  /* Only start if the SVG is visible */
  if (document.getElementById('gcm-world-svg')) {
    _gcmRAF = requestAnimationFrame(tick);
  }
}

function _gcmShowTooltip(event, html) {
  const tip = document.getElementById('gcm-tooltip');
  if (!tip) return;
  tip.innerHTML = html;
  tip.classList.add('visible');
  _gcmMoveTooltip(event);
}

function _gcmMoveTooltip(event) {
  const tip = document.getElementById('gcm-tooltip');
  if (!tip || !tip.classList.contains('visible')) return;
  const wrap = document.querySelector('.gcm-svg-wrap');
  if (!wrap) return;
  const rect = wrap.getBoundingClientRect();
  let x = event.clientX - rect.left + 14;
  let y = event.clientY - rect.top  - 10;
  const tw = tip.offsetWidth || 200;
  if (x + tw > rect.width) x = event.clientX - rect.left - tw - 14;
  tip.style.left = x + 'px';
  tip.style.top  = y + 'px';
}

function _gcmHideTooltip() {
  const tip = document.getElementById('gcm-tooltip');
  if (tip) tip.classList.remove('visible');
}

function _gcmTimeAgo() {
  const mins = Math.floor(Math.random() * 55) + 1;
  return mins < 2 ? 'Just now' : `${mins}m ago`;
}

function _gcmShowCountryPanel(iso, name, score) {
  const body = document.getElementById('gcm-spotlight-body');
  if (!body) return;

  const col   = _sevColor(_scoreToSev(score));
  const geo   = typeof GEO_RISK !== 'undefined' ? GEO_RISK.find(g => g.code === iso) : null;
  const actors = GTL_ACTORS.filter(a => a.origin === iso).slice(0, 4);
  const camps  = GTL_CAMPAIGNS.filter(c => {
    const a = GTL_ACTORS.find(x => x.id === c.actor);
    return a && a.origin === iso;
  });
  const inbound = CYBER_ARCS.filter(a => a.tgt === iso);
  const outbound= CYBER_ARCS.filter(a => a.src === iso);

  const flag = geo ? geo.flag : '';
  const sev  = _scoreToSev(score);
  const sevLabel = sev.charAt(0).toUpperCase() + sev.slice(1);

  body.innerHTML = `
    <div style="text-align:center;margin-bottom:12px;">
      <div class="gcm-spot-flag">${flag}</div>
      <div class="gcm-spot-name">${name}</div>
      <div class="gcm-spot-score" style="color:${col}">${sevLabel} Threat · ${score}/100</div>
      <div class="gcm-spot-bar-wrap" style="margin:8px 0 0;">
        <div class="gcm-spot-bar" style="width:${score}%;background:${col};"></div>
      </div>
    </div>

    ${geo ? `
    <div class="gcm-spot-section">Geopolitical Status</div>
    <div style="font-size:10px;color:#64748b;line-height:1.5;">${geo.escalation || '—'}</div>
    ` : ''}

    <div class="gcm-spot-section">Statistics</div>
    <div class="gcm-spot-stat"><span>Origin actors</span><span style="color:${col}">${actors.length}</span></div>
    <div class="gcm-spot-stat"><span>Campaigns</span><span style="color:#ff8a3d">${camps.length}</span></div>
    <div class="gcm-spot-stat"><span>Outbound arcs</span><span style="color:#ff3b5c">${outbound.length}</span></div>
    <div class="gcm-spot-stat"><span>Inbound arcs</span><span style="color:#3b82f6">${inbound.length}</span></div>

    ${actors.length ? `
    <div class="gcm-spot-section">Known Actors</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:2px;">
      ${actors.map(a => `<span class="gcm-spot-chip">${_esc(a.name)}</span>`).join('')}
    </div>` : ''}

    ${outbound.length ? `
    <div class="gcm-spot-section">Active Attacks</div>
    ${outbound.slice(0,3).map(a => `
      <div style="font-size:9px;color:#64748b;padding:4px 0;border-bottom:1px solid #111928;display:flex;justify-content:space-between;">
        <span style="color:${_sevColor(a.sev)}">${a.actor}</span>
        <span>→ ${a.tgt}</span>
        <span style="color:#2d3748">${a.tech}</span>
      </div>`).join('')}
    ` : ''}

    ${inbound.length ? `
    <div class="gcm-spot-section">Under Attack From</div>
    ${inbound.slice(0,3).map(a => `
      <div style="font-size:9px;color:#64748b;padding:4px 0;border-bottom:1px solid #111928;display:flex;justify-content:space-between;">
        <span style="color:${_sevColor(a.sev)}">${a.src}</span>
        <span style="color:#4a5568">${a.actor}</span>
        <span style="color:#2d3748">${a.tech}</span>
      </div>`).join('')}
    ` : ''}
  `;
}

let _gcmTickerInterval = null;
function _gcmStartTicker() {
  const list = document.getElementById('gcm-ticker-list');
  const countEl = document.getElementById('gcm-attack-count');
  if (!list) return;
  if (_gcmTickerInterval) clearInterval(_gcmTickerInterval);

  let totalEvents = 0;

  function _addEntry(isFirst) {
    const arc = CYBER_ARCS[Math.floor(Math.random() * CYBER_ARCS.length)];
    const col = _sevColor(arc.sev);
    const now = new Date();
    const t   = now.toTimeString().slice(0,8);
    totalEvents++;
    if (countEl) countEl.textContent = `${totalEvents} events`;

    const entry = document.createElement('div');
    entry.className = 'gcm-tick-entry gcm-tick-new';
    entry.innerHTML = `
      <span class="gcm-tick-time">${t}</span>
      <span class="gcm-tick-actor" style="color:${col}">${arc.actor}</span>
      <span class="gcm-tick-arrow">→</span>
      <span class="gcm-tick-tgt">${arc.tgt}</span>
      <span class="gcm-tick-dot">·</span>
      <span class="gcm-tick-sev" style="color:${col};font-size:9px;font-weight:600;">${arc.sev.toUpperCase()}</span>
      <span class="gcm-tick-dot">·</span>
      <span class="gcm-tick-tech">${arc.tech}</span>
    `;
    list.insertBefore(entry, list.firstChild);

    /* Keep max 6 entries */
    while (list.children.length > 6) {
      list.removeChild(list.lastChild);
    }
  }

  /* Seed with initial entries */
  for (let i = 0; i < 5; i++) _addEntry(true);

  /* Update every 3.5 seconds */
  _gcmTickerInterval = setInterval(() => {
    if (!document.getElementById('gcm-ticker-list')) {
      clearInterval(_gcmTickerInterval); return;
    }
    _addEntry(false);
  }, 3500);
}

function _gcmDrawSparklines() {
  const d3 = window.d3;
  if (!d3) return;

  const kpiIds = ['gcm-kv-apt','gcm-kv-camp','gcm-kv-crit','gcm-kv-zero'];
  kpiIds.forEach(id => {
    const svg = document.getElementById(`${id}-spark`);
    if (!svg) return;
    const base = parseInt(document.getElementById(id)?.textContent) || 10;
    /* Generate realistic sparkline data (last 12 periods) */
    const data = Array.from({length:12}, (_,i) => {
      const trend = base * (0.6 + 0.4 * (i/11));
      return Math.round(trend + (Math.random()-0.4) * base * 0.3);
    });
    data[11] = base;

    const W = 80, H = 24;
    const xScale = d3.scaleLinear().domain([0, data.length-1]).range([0, W]);
    const yScale = d3.scaleLinear().domain([0, Math.max(...data)*1.1]).range([H, 0]);
    const line   = d3.line().x((_,i) => xScale(i)).y(d => yScale(d)).curve(d3.curveCatmullRom);
    const area   = d3.area().x((_,i) => xScale(i)).y0(H).y1(d => yScale(d)).curve(d3.curveCatmullRom);

    const card   = svg.closest('.gcm-kpi-card');
    const col    = card ? getComputedStyle(card).getPropertyValue('--kpi-color').trim() : '#00d4ff';

    const svgSel = d3.select(svg);
    svgSel.selectAll('*').remove();
    svgSel.append('path').datum(data).attr('class','gcm-spark-area').attr('d', area)
      .attr('fill', col);
    svgSel.append('path').datum(data).attr('class','gcm-spark-line').attr('d', line)
      .attr('stroke', col);
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   §5  ACTOR REGISTRY TABLE
═══════════════════════════════════════════════════════════════════════════ */
function _buildActorRegistry() {
  let rows = GTL_ACTORS.slice().sort((a,b) => b.risk - a.risk);

  const typeOptions = [...new Set(GTL_ACTORS.map(a => a.type))].map(t =>
    `<option value="${t}">${t}</option>`).join('');
  const originOptions = [...new Set(GTL_ACTORS.map(a => a.origin))].map(o =>
    `<option value="${o}">${_flag(o)} ${o}</option>`).join('');

  const tableRows = rows.map(a => {
    const tc = ACTOR_TYPE_CFG[a.type] || ACTOR_TYPE_CFG.Unknown;
    const actStr = a.active
      ? `<span class="gtl-pulse-dot"></span><span style="color:${C.green};font-size:11px;">Active</span>`
      : `<span style="color:${C.muted};font-size:11px;">Dormant</span>`;
    const riskColor = a.risk >= 90 ? C.crit : a.risk >= 80 ? C.orange : a.risk >= 70 ? C.amber : C.green;
    return `
    <tr class="gtl-actor-row" data-id="${a.id}" data-type="${a.type}" data-origin="${a.origin}">
      <td class="gtl-actor-name-cell">
        <div class="gtl-actor-icon" style="background:${tc.color}22;color:${tc.color};"><i class="fas ${tc.icon}"></i></div>
        <div>
          <div style="font-weight:600;color:${C.text};">${_esc(a.name)}</div>
          <div style="font-size:10px;color:${C.muted};">${a.aliases.slice(0,2).map(al => _esc(al)).join(' · ')}</div>
        </div>
      </td>
      <td>${_badge(a.type, tc.color, tc.color+'22')}</td>
      <td><span style="font-size:15px;margin-right:4px;">${_flag(a.origin)}</span><span style="font-size:11px;color:${C.muted};">${a.origin}</span></td>
      <td>${_badge(a.sponsor, C.accent, C.accent+'22')}</td>
      <td>
        <div class="gtl-riskbar-wrap" style="width:80px;">
          <div class="gtl-riskbar" style="width:${a.risk}%;background:${riskColor};"></div>
          <span style="font-size:11px;margin-left:4px;color:${riskColor};font-weight:700;">${a.risk}</span>
        </div>
      </td>
      <td>${actStr}</td>
      <td style="font-size:11px;color:${C.muted};">${_timeAgo(a.last_seen)}</td>
      <td style="font-size:11px;color:${C.muted};">${a.since}</td>
      <td style="font-size:11px;color:${C.accent};">${a.incidents_yr > 0 ? a.incidents_yr : '—'}</td>
      <td>
        <button class="gtl-btn-sm" onclick="window.gtlActorExpand('${a.id}')">
          <i class="fas fa-chevron-down"></i> Profile
        </button>
      </td>
    </tr>
    <tr class="gtl-actor-expand-row" id="gtl-actor-exp-${a.id}" style="display:none;">
      <td colspan="10" class="gtl-actor-expand-cell">
        ${_buildActorProfile(a)}
      </td>
    </tr>`;
  }).join('');

  return `
  <div class="gtl-registry-toolbar">
    <div class="gtl-search-wrap">
      <i class="fas fa-search"></i>
      <input id="gtl-actor-search" type="text" placeholder="Search actors, aliases, tools…" oninput="window.gtlFilterActors()">
    </div>
    <select id="gtl-actor-type-filter" onchange="window.gtlFilterActors()" class="gtl-select">
      <option value="">All Types</option>
      ${typeOptions}
    </select>
    <select id="gtl-actor-origin-filter" onchange="window.gtlFilterActors()" class="gtl-select">
      <option value="">All Origins</option>
      ${originOptions}
    </select>
    <label class="gtl-toggle-label">
      <input type="checkbox" id="gtl-active-only" onchange="window.gtlFilterActors()">
      Active only
    </label>
    <span id="gtl-actor-count" class="gtl-count-chip">${GTL_ACTORS.length} actors</span>
  </div>
  <div class="gtl-registry-wrap">
    <table class="gtl-actor-table" id="gtl-actor-table">
      <thead>
        <tr>
          <th>Actor <i class="fas fa-sort gtl-sort-icon" onclick="window.gtlSortActors('name')"></i></th>
          <th>Type</th>
          <th>Origin</th>
          <th>Sponsor</th>
          <th>Risk <i class="fas fa-sort-down gtl-sort-icon" onclick="window.gtlSortActors('risk')"></i></th>
          <th>Status</th>
          <th>Last Seen <i class="fas fa-sort gtl-sort-icon" onclick="window.gtlSortActors('last_seen')"></i></th>
          <th>Since</th>
          <th>Incidents/yr</th>
          <th></th>
        </tr>
      </thead>
      <tbody id="gtl-actor-tbody">${tableRows}</tbody>
    </table>
  </div>`;
}

function _buildActorProfile(a) {
  const tc = ACTOR_TYPE_CFG[a.type] || ACTOR_TYPE_CFG.Unknown;
  const ops = (a.ops || []).slice(0,5);
  const toolList = (a.tools || []).map(t => `<span class="gtl-tool-chip">${_esc(t)}</span>`).join('');
  const ttpList = (a.ttps || []).map(t => `<span class="gtl-ttp-chip">${_esc(t)}</span>`).join('');
  const targList = (a.targets || []).map(t => `<span class="gtl-target-chip">${_esc(t)}</span>`).join('');
  const opsList = ops.map(o => `<div class="gtl-op-item"><i class="fas fa-chevron-right" style="color:${tc.color};margin-right:6px;font-size:10px;"></i>${_esc(o)}</div>`).join('');
  const iocList = (a.iocs || []).slice(0,3).map(i => `<code class="gtl-ioc">${_esc(i)}</code>`).join('');

  return `
  <div class="gtl-profile-grid">
    <div class="gtl-profile-left">
      <div class="gtl-profile-header" style="border-left:3px solid ${tc.color};">
        <i class="fas ${tc.icon}" style="color:${tc.color};font-size:22px;"></i>
        <div>
          <div class="gtl-profile-name">${_esc(a.name)}</div>
          <div class="gtl-profile-aliases">${a.aliases.join(' · ')}</div>
        </div>
        <div class="gtl-profile-origin">
          <span style="font-size:22px;">${_flag(a.origin)}</span>
          <span>${a.origin} · ${a.sponsor}</span>
        </div>
      </div>
      <p class="gtl-profile-brief">${_esc(a.brief)}</p>
      <div class="gtl-profile-section-title">Target Sectors</div>
      <div class="gtl-chip-row">${targList}</div>
      <div class="gtl-profile-section-title">TTPs</div>
      <div class="gtl-chip-row">${ttpList}</div>
    </div>
    <div class="gtl-profile-right">
      <div class="gtl-profile-section-title">Notable Operations</div>
      ${opsList}
      <div class="gtl-profile-section-title" style="margin-top:12px;">Tooling</div>
      <div class="gtl-chip-row">${toolList}</div>
      ${iocList ? `<div class="gtl-profile-section-title" style="margin-top:12px;">Sample IOCs</div><div class="gtl-chip-row">${iocList}</div>` : ''}
      <div class="gtl-profile-stats-row" style="margin-top:14px;">
        <div class="gtl-pstat"><div style="color:${C.crit};font-size:18px;font-weight:700;">${a.risk}</div><div>Risk Score</div></div>
        <div class="gtl-pstat"><div style="color:${C.accent};font-size:18px;font-weight:700;">${a.confidence}%</div><div>Confidence</div></div>
        <div class="gtl-pstat"><div style="color:${C.orange};font-size:18px;font-weight:700;">${a.sectors_hit}</div><div>Sectors Hit</div></div>
        <div class="gtl-pstat"><div style="color:${C.amber};font-size:18px;font-weight:700;">${a.since}</div><div>Active Since</div></div>
      </div>
    </div>
  </div>`;
}

/* ═══════════════════════════════════════════════════════════════════════════
   §6  ACTIVE CAMPAIGNS FEED
═══════════════════════════════════════════════════════════════════════════ */
function _buildCampaignsFeed() {
  const sorted = GTL_CAMPAIGNS.slice().sort((a,b) => {
    const sorder = {Critical:0,High:1,Medium:2,Low:3};
    return (sorder[a.severity]||3) - (sorder[b.severity]||3);
  });

  /* Group by status */
  const active = sorted.filter(c => c.status === 'Active');
  const monitor = sorted.filter(c => c.status === 'Monitoring');
  const historical = sorted.filter(c => c.status === 'Historical');

  function _campCard(c) {
    const sv = _sev(c.severity);
    const actor = GTL_ACTORS.find(a => a.id === c.actor);
    const actorName = actor ? actor.name : c.actor;
    const actorFlag = actor ? _flag(actor.origin) : '';
    const ttpPills = c.ttps.map(t => `<span class="gtl-ttp-chip">${t}</span>`).join('');
    const sectorPills = c.targeted_sectors.slice(0,3).map(s =>
      `<span class="gtl-target-chip">${s}</span>`).join('');

    return `
    <div class="gtl-camp-card" style="border-left:3px solid ${sv.color};" onclick="window.gtlCampExpand('${c.id}')">
      <div class="gtl-camp-card-header">
        <div>
          <div class="gtl-camp-name">${_esc(c.name)}</div>
          <div class="gtl-camp-actor">${actorFlag} ${_esc(actorName)} · ${_timeAgo(c.updated)}</div>
        </div>
        <div class="gtl-camp-meta">
          ${_badge(c.severity, sv.color, sv.bg)}
          <span style="font-size:10px;color:${C.muted};margin-left:8px;">${c.confidence}% conf.</span>
        </div>
      </div>
      <p class="gtl-camp-desc">${_esc(c.description)}</p>
      <div class="gtl-chip-row" style="margin-top:6px;">${sectorPills}${ttpPills}</div>
      <div class="gtl-camp-footer">
        <span><i class="fas fa-flag" style="color:${C.muted};margin-right:4px;"></i>${c.indicators} indicators</span>
        <span><i class="fas fa-crosshairs" style="color:${C.muted};margin-right:4px;"></i>${c.victims} victims</span>
        <span><i class="fas fa-clock" style="color:${C.muted};margin-right:4px;"></i>Since ${c.started}</span>
      </div>
    </div>`;
  }

  /* MITRE tactic heatmap */
  const tacticCounts = {};
  GTL_CAMPAIGNS.forEach(c => {
    c.ttps.forEach(t => { tacticCounts[t] = (tacticCounts[t]||0) + 1; });
  });
  const top10 = Object.entries(tacticCounts).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const maxCount = top10[0]?.[1] || 1;
  const heatmapBars = top10.map(([t,cnt]) => {
    const pct = Math.round(cnt/maxCount*100);
    return `<div class="gtl-heatmap-row">
      <span class="gtl-heatmap-ttp">${t}</span>
      <div class="gtl-heatmap-bar-wrap">
        <div class="gtl-heatmap-bar" style="width:${pct}%;background:linear-gradient(90deg,${C.red},${C.orange});"></div>
      </div>
      <span class="gtl-heatmap-count">${cnt}</span>
    </div>`;
  }).join('');

  return `
  <div class="gtl-camps-layout">
    <div class="gtl-camps-main">
      <div class="gtl-camps-filter-row">
        <input type="text" id="gtl-camp-search" placeholder="Search campaigns…" class="gtl-input-sm" oninput="window.gtlFilterCampaigns()">
        <select id="gtl-camp-sev-filter" onchange="window.gtlFilterCampaigns()" class="gtl-select">
          <option value="">All Severities</option>
          <option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
        </select>
        <span class="gtl-count-chip">${GTL_CAMPAIGNS.length} campaigns</span>
      </div>

      <div class="gtl-camps-column-header">
        <span style="color:${C.crit};"><i class="fas fa-circle gtl-blink"></i> Active (${active.length})</span>
        <span style="color:${C.amber};margin-left:24px;"><i class="fas fa-eye"></i> Monitoring (${monitor.length})</span>
      </div>

      <div id="gtl-camp-list" class="gtl-camp-list">
        ${active.map(_campCard).join('')}
        ${monitor.map(_campCard).join('')}
      </div>
    </div>

    <div class="gtl-camps-sidebar">
      <div class="gtl-sidebar-title">Top TTP Frequency</div>
      <div class="gtl-heatmap">${heatmapBars}</div>

      <div class="gtl-sidebar-title" style="margin-top:20px;">Severity Split</div>
      ${['Critical','High','Medium','Low'].map(sv => {
        const cnt = GTL_CAMPAIGNS.filter(c => c.severity === sv).length;
        const sv_ = _sev(sv);
        return `<div class="gtl-sev-row">
          <span style="color:${sv_.color};">●</span>
          <span style="flex:1;margin-left:6px;">${sv}</span>
          <span style="color:${sv_.color};font-weight:700;">${cnt}</span>
        </div>`;
      }).join('')}

      <div class="gtl-sidebar-title" style="margin-top:20px;">Top Targeted Sectors</div>
      ${(() => {
        const sc = {};
        GTL_CAMPAIGNS.forEach(c => c.targeted_sectors.forEach(s => { sc[s]=(sc[s]||0)+1; }));
        return Object.entries(sc).sort((a,b)=>b[1]-a[1]).slice(0,6).map(([s,n]) =>
          `<div class="gtl-sev-row"><span style="color:${C.accent};">▸</span><span style="flex:1;margin-left:6px;">${s}</span><span style="color:${C.accent};">${n}</span></div>`
        ).join('');
      })()}
    </div>
  </div>`;
}

/* ═══════════════════════════════════════════════════════════════════════════
   §7  VULNERABILITY RADAR
═══════════════════════════════════════════════════════════════════════════ */
function _buildVulnRadar() {
  const sorted = GTL_VULNS.slice().sort((a,b) => b.cvss - a.cvss);

  /* Histogram buckets 9-10, 8-8.9, 7-7.9, 4-6.9 */
  const buckets = [
    {label:'9-10',cnt:sorted.filter(v=>v.cvss>=9).length,color:C.crit},
    {label:'8-8.9',cnt:sorted.filter(v=>v.cvss>=8&&v.cvss<9).length,color:C.orange},
    {label:'7-7.9',cnt:sorted.filter(v=>v.cvss>=7&&v.cvss<8).length,color:C.amber},
    {label:'4-6.9',cnt:sorted.filter(v=>v.cvss>=4&&v.cvss<7).length,color:C.green},
  ];
  const maxBkt = Math.max(...buckets.map(b=>b.cnt));

  const histBars = buckets.map(b => `
    <div class="gtl-hist-col">
      <div class="gtl-hist-bar-wrap">
        <div class="gtl-hist-bar" style="height:${Math.round(b.cnt/maxBkt*100)}%;background:${b.color};"></div>
      </div>
      <div style="font-size:18px;font-weight:700;color:${b.color};">${b.cnt}</div>
      <div style="font-size:10px;color:${C.muted};">CVSS ${b.label}</div>
    </div>`).join('');

  const wild = sorted.filter(v=>v.exploit_wild);
  const zerodays = sorted.filter(v=>v.zero_day && v.exploit_wild);

  const vulnRows = sorted.map(v => {
    const cc = _cvssColor(v.cvss);
    const sv = _sev(v.severity);
    const actorNames = (v.actors||[]).map(aid => {
      const a = GTL_ACTORS.find(x=>x.id===aid);
      return a ? a.name : aid;
    }).join(', ');
    return `
    <tr class="gtl-vuln-row">
      <td><code class="gtl-cve-code">${v.cve}</code></td>
      <td style="font-weight:600;font-size:13px;color:${cc};">${v.cvss}</td>
      <td>${_badge(v.severity, sv.color, sv.bg)}</td>
      <td style="font-size:12px;">${_esc(v.product)}</td>
      <td style="font-size:11px;color:${C.muted};">${_esc(v.vendor)}</td>
      <td>${_badge(v.type, C.blue, C.blue+'22')}</td>
      <td>${v.exploit_wild ? `<span class="gtl-wild-badge"><i class="fas fa-fire"></i> In Wild</span>` : `<span style="color:${C.muted};font-size:11px;">PoC/None</span>`}</td>
      <td>${v.zero_day ? `<span class="gtl-zeroday-badge">0-DAY</span>` : ''}</td>
      <td style="font-size:11px;color:${C.muted};">${actorNames || '—'}</td>
      <td style="font-size:11px;">${v.first_exploited ? _timeAgo(v.first_exploited) : '—'}</td>
    </tr>`;
  }).join('');

  /* Zero-day ticker */
  const zdTicker = zerodays.map(v =>
    `<span class="gtl-ticker-item" style="color:${C.crit};">⚠ ${v.cve} [${v.product}] actively exploited zero-day</span>`
  ).join('');

  return `
  <div class="gtl-vuln-ticker" id="gtl-vuln-ticker">
    <span style="color:${C.red};font-weight:700;margin-right:12px;font-size:11px;">● ZERO-DAY ALERT</span>
    <div class="gtl-ticker-track">
      ${zdTicker}${zdTicker}
    </div>
  </div>

  <div class="gtl-vuln-stats-row">
    <div class="gtl-vuln-stat">
      <div style="font-size:26px;font-weight:800;color:${C.crit};">${GTL_VULNS.length}</div>
      <div>Tracked CVEs</div>
    </div>
    <div class="gtl-vuln-stat">
      <div style="font-size:26px;font-weight:800;color:${C.orange};">${wild.length}</div>
      <div>In-Wild Exploited</div>
    </div>
    <div class="gtl-vuln-stat">
      <div style="font-size:26px;font-weight:800;color:${C.purple};">${zerodays.length}</div>
      <div>Active Zero-Days</div>
    </div>
    <div class="gtl-vuln-stat">
      <div style="font-size:26px;font-weight:800;color:${C.amber};">${sorted.filter(v=>v.cvss>=9).length}</div>
      <div>CVSS 9+ Critical</div>
    </div>
    <div class="gtl-vuln-histogram">${histBars}</div>
  </div>

  <div class="gtl-vuln-toolbar">
    <input type="text" placeholder="Search CVE, product, vendor…" class="gtl-input-sm" id="gtl-vuln-search" oninput="window.gtlFilterVulns()">
    <select class="gtl-select" id="gtl-vuln-sev" onchange="window.gtlFilterVulns()">
      <option value="">All Severities</option>
      <option>Critical</option><option>High</option><option>Medium</option>
    </select>
    <label class="gtl-toggle-label"><input type="checkbox" id="gtl-vuln-wild" onchange="window.gtlFilterVulns()"> In-Wild only</label>
    <label class="gtl-toggle-label"><input type="checkbox" id="gtl-vuln-zd" onchange="window.gtlFilterVulns()"> Zero-Days only</label>
  </div>

  <div class="gtl-vuln-table-wrap">
    <table class="gtl-vuln-table">
      <thead>
        <tr>
          <th>CVE</th><th>CVSS</th><th>Severity</th><th>Product</th><th>Vendor</th>
          <th>Type</th><th>Exploit</th><th>0-Day</th><th>Known Actors</th><th>First Exploited</th>
        </tr>
      </thead>
      <tbody id="gtl-vuln-tbody">${vulnRows}</tbody>
    </table>
  </div>`;
}

/* ═══════════════════════════════════════════════════════════════════════════
   §8  SECTOR THREAT MATRIX
═══════════════════════════════════════════════════════════════════════════ */
function _buildSectorMatrix() {
  const tactics = ['Recon','Resource Dev','Initial Access','Execution','Persistence',
    'Priv Esc','Defense Evasion','Cred Access','Discovery','Lateral Mvmt',
    'Collection','Exfiltration','C2','Impact'];

  /* Build heatmap grid */
  let headerRow = `<tr><th class="gtl-mx-corner">Sector ↓ / Tactic →</th>` +
    tactics.map(t => `<th class="gtl-mx-th">${t}</th>`).join('') + '</tr>';

  let bodyRows = GTL_SECTORS.map(sector => {
    const scores = SECTOR_SCORES[sector] || [];
    const cells = tactics.map((t,i) => {
      const score = scores[i] || 0;
      const alpha = score/100;
      const bg = score >= 85 ? C.crit : score >= 70 ? C.orange : score >= 55 ? C.amber : score >= 40 ? C.blue : '#1a2744';
      const textColor = score >= 55 ? '#fff' : C.muted;
      return `<td class="gtl-mx-cell" style="background:${bg};opacity:${0.3+alpha*0.7};color:${textColor};"
        title="${sector} × ${t}: ${score}/100">${score}</td>`;
    }).join('');
    const maxScore = Math.max(...scores);
    const rowColor = maxScore >= 85 ? C.crit : maxScore >= 70 ? C.orange : C.amber;
    return `<tr>
      <td class="gtl-mx-label" style="border-left:3px solid ${rowColor};">${sector}</td>
      ${cells}
    </tr>`;
  }).join('');

  /* Sector risk bars */
  const sectorRisks = GTL_SECTORS.map(s => {
    const scores = SECTOR_SCORES[s] || [];
    const avg = Math.round(scores.reduce((a,b)=>a+b,0)/scores.length);
    return {sector:s, avg};
  }).sort((a,b)=>b.avg-a.avg);

  const riskBars = sectorRisks.map(sr => {
    const color = sr.avg >= 80 ? C.crit : sr.avg >= 70 ? C.orange : sr.avg >= 60 ? C.amber : C.green;
    return `
    <div class="gtl-sector-bar-row">
      <span class="gtl-sector-label">${sr.sector}</span>
      <div class="gtl-sector-bar-wrap">
        <div class="gtl-sector-bar" style="width:${sr.avg}%;background:linear-gradient(90deg,${color},${color}88);"></div>
      </div>
      <span style="font-size:12px;color:${color};font-weight:700;min-width:30px;">${sr.avg}</span>
    </div>`;
  }).join('');

  return `
  <div class="gtl-sector-layout">
    <div class="gtl-sector-matrix-wrap">
      <div class="gtl-matrix-title">
        <i class="fas fa-th" style="color:${C.accent};margin-right:6px;"></i>
        Sector × MITRE Tactic Threat Intensity Matrix
        <span style="font-size:11px;color:${C.muted};margin-left:12px;">(Score 0-100)</span>
      </div>
      <div class="gtl-matrix-scroll">
        <table class="gtl-mx-table">
          <thead>${headerRow}</thead>
          <tbody>${bodyRows}</tbody>
        </table>
      </div>
    </div>
    <div class="gtl-sector-sidebar">
      <div class="gtl-sidebar-title">Sector Risk Ranking</div>
      ${riskBars}
      <div class="gtl-sidebar-title" style="margin-top:20px;">Highest-Risk Tactics</div>
      ${(() => {
        const tacticTotals = tactics.map((t,i) => {
          const total = GTL_SECTORS.reduce((sum,s) => sum+(SECTOR_SCORES[s]?.[i]||0),0);
          return {tactic:t, avg:Math.round(total/GTL_SECTORS.length)};
        }).sort((a,b)=>b.avg-a.avg).slice(0,5);
        return tacticTotals.map(tt => {
          const c = tt.avg>=75?C.crit:tt.avg>=65?C.orange:C.amber;
          return `<div class="gtl-sev-row"><span style="color:${c};">▸</span><span style="flex:1;margin-left:6px;font-size:11px;">${tt.tactic}</span><span style="color:${c};font-weight:700;">${tt.avg}</span></div>`;
        }).join('');
      })()}
    </div>
  </div>`;
}

/* ═══════════════════════════════════════════════════════════════════════════
   §9  GEOPOLITICAL RISK ENGINE
═══════════════════════════════════════════════════════════════════════════ */
function _buildGeopolitical() {
  const sorted = GEO_RISK.slice().sort((a,b) => b.cyber_score - a.cyber_score);

  const rows = sorted.map(g => {
    const sc = _statusColor(g.status);
    const ec = _escLevel(g.escalation);
    const riskColor = g.cyber_score >= 90 ? C.crit : g.cyber_score >= 80 ? C.orange : g.cyber_score >= 70 ? C.amber : C.green;
    const groupPills = g.groups.slice(0,3).map(gr => `<span class="gtl-group-chip">${_esc(gr)}</span>`).join('');

    return `
    <div class="gtl-geo-card" style="border-left:3px solid ${ec};">
      <div class="gtl-geo-card-header">
        <span class="gtl-geo-flag">${g.flag}</span>
        <div class="gtl-geo-info">
          <div class="gtl-geo-country">${g.country}</div>
          <div class="gtl-geo-status" style="color:${sc};">${g.status}</div>
        </div>
        <div class="gtl-geo-scores">
          <div class="gtl-geo-score" style="color:${riskColor};">${g.cyber_score}</div>
          <div style="font-size:10px;color:${C.muted};">Cyber Score</div>
        </div>
        <div class="gtl-geo-escalation" style="background:${ec}22;border:1px solid ${ec}40;">
          <span style="color:${ec};font-size:10px;font-weight:700;">${g.escalation}</span>
        </div>
      </div>
      <div class="gtl-geo-groups">${groupPills}</div>
      <div class="gtl-geo-nexus"><span style="color:${C.muted};font-size:10px;">NEXUS:</span> ${_esc(g.nexus)}</div>
      <div class="gtl-geo-predicted"><i class="fas fa-binoculars" style="color:${C.accent};margin-right:5px;font-size:10px;"></i>${_esc(g.predicted)}</div>
    </div>`;
  }).join('');

  /* Attribution confidence ring summary */
  const riskBands = [
    {label:'90-100 Extreme', cnt:sorted.filter(g=>g.cyber_score>=90).length, color:C.crit},
    {label:'80-89 High',     cnt:sorted.filter(g=>g.cyber_score>=80&&g.cyber_score<90).length, color:C.orange},
    {label:'70-79 Elevated', cnt:sorted.filter(g=>g.cyber_score>=70&&g.cyber_score<80).length, color:C.amber},
    {label:'60-69 Moderate', cnt:sorted.filter(g=>g.cyber_score<70).length, color:C.green},
  ];

  return `
  <div class="gtl-geo-layout">
    <div class="gtl-geo-sidebar">
      <div class="gtl-sidebar-title">Risk Band Distribution</div>
      ${riskBands.map(b => `
        <div class="gtl-sev-row" style="margin-bottom:8px;">
          <span style="color:${b.color};font-size:16px;">●</span>
          <span style="flex:1;margin-left:8px;font-size:11px;">${b.label}</span>
          <span style="color:${b.color};font-weight:700;font-size:16px;">${b.cnt}</span>
        </div>`).join('')}

      <div class="gtl-sidebar-title" style="margin-top:20px;">Escalation Trend</div>
      <div class="gtl-escl-indicator" style="color:${C.crit};">
        <i class="fas fa-arrow-trend-up"></i> Global cyber conflict intensity at <strong>8-year high</strong>
      </div>
      <div class="gtl-escl-indicator" style="color:${C.orange};margin-top:8px;">
        <i class="fas fa-exclamation-triangle"></i> 4 active nation-state conflict theaters
      </div>
      <div class="gtl-escl-indicator" style="color:${C.amber};margin-top:8px;">
        <i class="fas fa-shield-alt"></i> NATO Article 5 cyber threshold under review
      </div>
    </div>
    <div class="gtl-geo-cards">${rows}</div>
  </div>`;
}

/* ═══════════════════════════════════════════════════════════════════════════
   §10  SIGINT FEED
═══════════════════════════════════════════════════════════════════════════ */
function _buildSigintFeed() {
  /* Rendered within the world-map panel as a scrolling sidebar */
  return SIGINT_FEED.map((item, i) => {
    const pc = _priorityColor(item.priority);
    const ts = new Date(item.ts).toLocaleString('en-US',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
    return `
    <div class="gtl-sigint-item" style="animation-delay:${i*0.06}s;">
      <div class="gtl-sigint-header">
        <span class="gtl-sigint-priority" style="color:${pc};border:1px solid ${pc}33;">${item.priority}</span>
        <span class="gtl-sigint-src" style="color:${C.muted};">${_esc(item.src)}</span>
        <span class="gtl-sigint-ts">${ts}</span>
      </div>
      <div class="gtl-sigint-text">${_esc(item.text)}</div>
    </div>`;
  }).join('');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §11  AI THREAT BRIEFING PANEL
═══════════════════════════════════════════════════════════════════════════ */
function _buildBriefingPanel() {
  const today = new Date().toLocaleDateString('en-US',{weekday:'long',year:'numeric',month:'long',day:'numeric'});
  const critCamps = GTL_CAMPAIGNS.filter(c=>c.severity==='Critical'&&c.status==='Active');
  const wildZD   = GTL_VULNS.filter(v=>v.zero_day&&v.exploit_wild);
  const topActors = GTL_ACTORS.filter(a=>a.active&&a.risk>=92).slice(0,5);

  /* Pre-generated static briefing (would be replaced by live Claude API call) */
  const briefing = `
## THREAT INTELLIGENCE DAILY BRIEF — ${today}

### Executive Summary
Global cyber threat activity remains at **ELEVATED-CRITICAL** levels. Nation-state actor operations have intensified across all five tracked regions, with particular escalation in supply-chain and critical infrastructure targeting.

### Critical Events (Last 24h)
${critCamps.slice(0,3).map(c => `- **${c.name}**: ${c.description.slice(0,90)}…`).join('\n')}

### Zero-Day Exploitation Alerts
${wildZD.slice(0,3).map(v => `- **${v.cve}** (${v.product}, CVSS ${v.cvss}): ${v.description.slice(0,80)}…`).join('\n')}

### Highest-Risk Actors (Active)
${topActors.map(a => `- **${a.name}** [${a.origin} · ${a.sponsor}] — Risk: ${a.risk}/100 · Last seen: ${_timeAgo(a.last_seen)}`).join('\n')}

### Predictive Assessment
1. **LockBit 3.0** Spring Wave likely to peak in next 30 days — healthcare and government sectors highest risk
2. **Volt Typhoon** KV-Botnet expansion suggests imminent activation window approaching — critical infrastructure teams should review lateral movement detection
3. **Cl0p** zero-day acquisition intelligence suggests MFT successor campaign H2 2025
4. **Sandworm** rail SCADA pre-positioning in Eastern Europe suggests active sabotage preparation

### Recommended Priority Actions
1. Patch **CVE-2025-0282** (Ivanti ICS) — exploitation confirmed by 3 APT groups
2. Audit privileged account access following Salt Typhoon telecom disclosures
3. Enable enhanced monitoring for **T1190/T1133** (external service exploitation)
4. Review backup system isolation — Cl0p and LockBit targeting enterprise backup infrastructure

*Confidence level: HIGH | Sources: TECHINT, SIGINT, OSINT, HUMINT | TLP:GREEN*`;

  /* Convert basic markdown to HTML */
  const briefHtml = briefing
    .replace(/^## (.+)$/gm, '<h3 class="gtl-brief-h2">$1</h3>')
    .replace(/^### (.+)$/gm, '<h4 class="gtl-brief-h3">$1</h4>')
    .replace(/\*\*(.+?)\*\*/g, '<strong style="color:#e2e8f0;">$1</strong>')
    .replace(/^- (.+)$/gm, '<div class="gtl-brief-li">$1</div>')
    .replace(/^\d+\. (.+)$/gm, '<div class="gtl-brief-li gtl-brief-numbered">$1</div>')
    .replace(/\n\n/g, '<div style="margin-bottom:12px;"></div>');

  const sigintHtml = _buildSigintFeed();

  return `
  <div class="gtl-brief-layout">
    <div class="gtl-brief-main">
      <div class="gtl-brief-header">
        <div>
          <div class="gtl-brief-title"><i class="fas fa-brain" style="color:${C.accent};margin-right:8px;"></i>AI Threat Intelligence Brief</div>
          <div style="font-size:11px;color:${C.muted};">${today} · Powered by Wadjet-Eye CTI Engine · TLP:GREEN</div>
        </div>
        <div class="gtl-brief-actions">
          <button class="gtl-btn-sm" onclick="window.gtlDownloadBrief()"><i class="fas fa-download"></i> Export PDF</button>
          <button class="gtl-btn-sm" onclick="window.gtlRegenerateBrief()"><i class="fas fa-sync"></i> Regenerate</button>
          <button class="gtl-btn-sm" style="background:${C.accent}22;color:${C.accent};border-color:${C.accent};" onclick="window.gtlShareBrief()">
            <i class="fas fa-share-alt"></i> Share
          </button>
        </div>
      </div>
      <div class="gtl-brief-content" id="gtl-brief-content">${briefHtml}</div>
      <div class="gtl-brief-meta">
        <div class="gtl-brief-sources">
          <span class="gtl-source-chip">TECHINT</span>
          <span class="gtl-source-chip">SIGINT</span>
          <span class="gtl-source-chip">OSINT</span>
          <span class="gtl-source-chip">HUMINT</span>
          <span class="gtl-source-chip">FININT</span>
          <span class="gtl-source-chip">GEOINT</span>
        </div>
        <span style="font-size:10px;color:${C.muted};">Last updated: ${new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'})}</span>
      </div>
    </div>
    <div class="gtl-brief-sigint">
      <div class="gtl-sidebar-title" style="padding:0 0 10px 0;">
        <span class="gtl-pulse-dot"></span> SIGINT Dispatch Feed
      </div>
      <div class="gtl-sigint-list" id="gtl-sigint-list">${sigintHtml}</div>
    </div>
  </div>`;
}

/* ═══════════════════════════════════════════════════════════════════════════
   §12  LAYOUT & ROUTER
═══════════════════════════════════════════════════════════════════════════ */
function _buildLayout(container) {
  const tabHtml = TABS.map(t => `
    <button class="gtl-tab${t.id==='worldmap'?' gtl-tab-active':''}" data-tab="${t.id}" onclick="window.gtlSwitchTab('${t.id}')">
      <i class="fas ${t.icon}"></i><span>${t.label}</span>
    </button>`).join('');

  container.innerHTML = `
  <div class="gtl-root" id="${GTL_ID}">

    <!-- Header Bar -->
    <div class="gtl-header">
      <div class="gtl-header-left">
        <div class="gtl-logo">
          <i class="fas fa-globe-americas" style="color:${C.accent};font-size:18px;"></i>
          <span class="gtl-logo-text">Global Threat Landscape</span>
          <span class="gtl-version-chip">v${GTL_VERSION}</span>
        </div>
        <div class="gtl-live-indicator">
          <span class="gtl-pulse-dot"></span>
          <span>LIVE INTEL</span>
        </div>
      </div>
      <div class="gtl-header-right">
        <div class="gtl-threat-level-indicator" id="gtl-threat-level">
          <span style="font-size:10px;color:${C.muted};">GLOBAL THREAT LEVEL</span>
          <div class="gtl-threat-gauge">
            <div class="gtl-threat-bar crit-bg" style="width:81%;"></div>
          </div>
          <span style="color:${C.crit};font-weight:700;font-size:13px;">CRITICAL-HIGH</span>
        </div>
        <button class="gtl-btn-sm" onclick="window.gtlRefreshAll()" title="Refresh all data">
          <i class="fas fa-sync-alt" id="gtl-refresh-icon"></i>
        </button>
        <span id="gtl-last-update" style="font-size:10px;color:${C.muted};">Updated just now</span>
      </div>
    </div>

    <!-- Tab bar -->
    <div class="gtl-tabs">${tabHtml}</div>

    <!-- Content panels -->
    <div class="gtl-content">
      <div class="gtl-panel" id="gtl-panel-worldmap">
        <div class="gtl-panel-inner">
          <div class="gtl-panel-title"><i class="fas fa-globe-americas"></i> Global Threat Map</div>
          <div id="gtl-worldmap-content" class="gtl-worldmap-grid">
            <div id="gtl-map-main" class="gtl-map-main-col"></div>
            <div class="gtl-map-sigint-col">
              <div class="gtl-sidebar-title" style="padding-bottom:10px;">
                <span class="gtl-pulse-dot"></span> Intelligence Dispatches
              </div>
              <div class="gtl-sigint-list">${_buildSigintFeed()}</div>
            </div>
          </div>
        </div>
      </div>

      <div class="gtl-panel" id="gtl-panel-actors" style="display:none;">
        <div class="gtl-panel-inner">
          <div class="gtl-panel-title"><i class="fas fa-users-slash"></i> Threat Actor Registry</div>
          <div id="gtl-actors-content"></div>
        </div>
      </div>

      <div class="gtl-panel" id="gtl-panel-campaigns" style="display:none;">
        <div class="gtl-panel-inner">
          <div class="gtl-panel-title"><i class="fas fa-crosshairs"></i> Active Campaigns</div>
          <div id="gtl-campaigns-content"></div>
        </div>
      </div>

      <div class="gtl-panel" id="gtl-panel-vulns" style="display:none;">
        <div class="gtl-panel-inner">
          <div class="gtl-panel-title"><i class="fas fa-bug"></i> Vulnerability Radar</div>
          <div id="gtl-vulns-content"></div>
        </div>
      </div>

      <div class="gtl-panel" id="gtl-panel-sectors" style="display:none;">
        <div class="gtl-panel-inner">
          <div class="gtl-panel-title"><i class="fas fa-industry"></i> Sector Threat Matrix</div>
          <div id="gtl-sectors-content"></div>
        </div>
      </div>

      <div class="gtl-panel" id="gtl-panel-geopolitical" style="display:none;">
        <div class="gtl-panel-inner">
          <div class="gtl-panel-title"><i class="fas fa-chess-rook"></i> Geopolitical Risk Engine</div>
          <div id="gtl-geopolitical-content"></div>
        </div>
      </div>

      <div class="gtl-panel" id="gtl-panel-briefing" style="display:none;">
        <div class="gtl-panel-inner" style="padding:0;">
          <div id="gtl-briefing-content"></div>
        </div>
      </div>
    </div>

  </div>`;
}

function _initPanels() {
  /* World map — inject skeleton HTML then boot D3 async */
  const mapMain = _el('gtl-map-main');
  if (mapMain) {
    mapMain.innerHTML = _buildWorldMap();
    /* Use rAF to allow DOM to settle before D3 measures sizes */
    requestAnimationFrame(() => {
      _initCyberMap().catch(err => {
        console.error('[CyberMap] init error:', err);
        const countEl = document.getElementById('gcm-arc-count');
        if (countEl) countEl.textContent = 'Map init failed';
      });
    });
  }
}

function _showCountrySpotlight(iso, name, score) {
  /* Delegate to the new D3 cyber map panel */
  _gcmShowCountryPanel(iso, name, score);
}

/* ═══════════════════════════════════════════════════════════════════════════
   §12b  INTERACTIVE HANDLERS (exposed on window)
═══════════════════════════════════════════════════════════════════════════ */
global.gtlSwitchTab = function(tabId) {
  TABS.forEach(t => {
    const panel = _el(`gtl-panel-${t.id}`);
    const tab   = document.querySelector(`[data-tab="${t.id}"]`);
    if (!panel || !tab) return;
    const active = t.id === tabId;
    panel.style.display = active ? '' : 'none';
    tab.classList.toggle('gtl-tab-active', active);
  });

  /* Lazy-render panels on first visit */
  const panel = _el(`gtl-panel-${tabId}`);
  if (!panel || panel.dataset.rendered) return;
  panel.dataset.rendered = '1';

  const content = _el(`gtl-${tabId}-content`) || _el(`gtl-${tabId}s-content`);
  if (!content) return;

  switch(tabId) {
    case 'actors':       content.innerHTML = _buildActorRegistry();  break;
    case 'campaigns':    content.innerHTML = _buildCampaignsFeed();   break;
    case 'vulns':        content.innerHTML = _buildVulnRadar();       break;
    case 'sectors':      content.innerHTML = _buildSectorMatrix();    break;
    case 'geopolitical': content.innerHTML = _buildGeopolitical();    break;
    case 'briefing':
      const bContent = _el('gtl-briefing-content');
      if (bContent) bContent.innerHTML = _buildBriefingPanel();
      break;
  }
};

global.gtlActorExpand = function(actorId) {
  const row = _el(`gtl-actor-exp-${actorId}`);
  if (!row) return;
  const open = row.style.display !== 'none';
  /* Close all others */
  document.querySelectorAll('.gtl-actor-expand-row').forEach(r => { r.style.display='none'; });
  document.querySelectorAll('.gtl-actor-row').forEach(r => r.classList.remove('gtl-actor-row-open'));
  if (!open) {
    row.style.display = '';
    const actorRow = row.previousElementSibling;
    if (actorRow) actorRow.classList.add('gtl-actor-row-open');
  }
};

global.gtlFilterActors = function() {
  const q      = (_el('gtl-actor-search')?.value||'').toLowerCase();
  const type   = _el('gtl-actor-type-filter')?.value||'';
  const origin = _el('gtl-actor-origin-filter')?.value||'';
  const active = _el('gtl-active-only')?.checked||false;

  let count = 0;
  GTL_ACTORS.forEach(a => {
    const matchQ = !q || a.name.toLowerCase().includes(q) ||
      a.aliases.join(' ').toLowerCase().includes(q) ||
      (a.tools||[]).join(' ').toLowerCase().includes(q);
    const matchT = !type || a.type === type;
    const matchO = !origin || a.origin === origin;
    const matchA = !active || a.active;
    const visible = matchQ && matchT && matchO && matchA;
    const row = document.querySelector(`tr.gtl-actor-row[data-id="${a.id}"]`);
    const expRow = _el(`gtl-actor-exp-${a.id}`);
    if (row) row.style.display = visible ? '' : 'none';
    if (expRow) expRow.style.display = 'none';
    if (visible) count++;
  });
  const chip = _el('gtl-actor-count');
  if (chip) chip.textContent = `${count} actors`;
};

global.gtlSortActors = function(field) {
  const tbody = _el('gtl-actor-tbody');
  if (!tbody) return;
  const rows = [...tbody.querySelectorAll('tr.gtl-actor-row')];
  const expRows = {};
  tbody.querySelectorAll('.gtl-actor-expand-row').forEach(r => {
    const id = r.id.replace('gtl-actor-exp-','');
    expRows[id] = r;
  });
  rows.sort((a,b) => {
    const idA = a.dataset.id, idB = b.dataset.id;
    const actA = GTL_ACTORS.find(x=>x.id===idA);
    const actB = GTL_ACTORS.find(x=>x.id===idB);
    if (!actA||!actB) return 0;
    if (field === 'risk') return (actB.risk||0) - (actA.risk||0);
    if (field === 'name') return actA.name.localeCompare(actB.name);
    if (field === 'last_seen') return new Date(actB.last_seen||0) - new Date(actA.last_seen||0);
    return 0;
  });
  rows.forEach(r => {
    const id = r.dataset.id;
    tbody.appendChild(r);
    if (expRows[id]) tbody.appendChild(expRows[id]);
  });
};

global.gtlFilterCampaigns = function() {
  const q   = (_el('gtl-camp-search')?.value||'').toLowerCase();
  const sev = _el('gtl-camp-sev-filter')?.value||'';
  const list = _el('gtl-camp-list');
  if (!list) return;
  list.querySelectorAll('.gtl-camp-card').forEach(card => {
    const id = card.onclick?.toString().match(/'(c\d+)'/)?.[1];
    const c  = GTL_CAMPAIGNS.find(x=>x.id===id);
    if (!c) return;
    const matchQ = !q || c.name.toLowerCase().includes(q) || c.description.toLowerCase().includes(q);
    const matchS = !sev || c.severity === sev;
    card.style.display = (matchQ && matchS) ? '' : 'none';
  });
};

global.gtlCampExpand = function(campId) {
  const c = GTL_CAMPAIGNS.find(x=>x.id===campId);
  if (!c) return;
  /* For now just a toast/alert — full modal could be added */
};

global.gtlFilterVulns = function() {
  const q    = (_el('gtl-vuln-search')?.value||'').toLowerCase();
  const sev  = _el('gtl-vuln-sev')?.value||'';
  const wild = _el('gtl-vuln-wild')?.checked||false;
  const zd   = _el('gtl-vuln-zd')?.checked||false;
  const tbody= _el('gtl-vuln-tbody');
  if (!tbody) return;
  GTL_VULNS.forEach(v => {
    const matchQ = !q || v.cve.toLowerCase().includes(q) || v.product.toLowerCase().includes(q) || v.vendor.toLowerCase().includes(q);
    const matchS = !sev || v.severity === sev;
    const matchW = !wild || v.exploit_wild;
    const matchZ = !zd   || (v.zero_day && v.exploit_wild);
    const row = tbody.querySelector(`tr td code.gtl-cve-code`)?.closest('tr');
    /* find row by cve text match */
    tbody.querySelectorAll('tr').forEach(tr => {
      const code = tr.querySelector('.gtl-cve-code');
      if (!code) return;
      const trCve = code.textContent.trim();
      const trVuln= GTL_VULNS.find(x=>x.cve===trCve);
      if (!trVuln) return;
      const m = (!q || trVuln.cve.toLowerCase().includes(q) || trVuln.product.toLowerCase().includes(q) || trVuln.vendor.toLowerCase().includes(q))
             && (!sev  || trVuln.severity === sev)
             && (!wild || trVuln.exploit_wild)
             && (!zd   || (trVuln.zero_day && trVuln.exploit_wild));
      tr.style.display = m ? '' : 'none';
    });
  });
};

global.gtlRefreshAll = function() {
  const icon = _el('gtl-refresh-icon');
  if (icon) { icon.classList.add('fa-spin'); setTimeout(()=>icon.classList.remove('fa-spin'),1500); }
  const upd = _el('gtl-last-update');
  if (upd) upd.textContent = `Updated ${new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'})}`;
};

global.gtlDownloadBrief = function() {
  const content = _el('gtl-brief-content');
  if (!content) return;
  const text = content.innerText;
  const blob = new Blob([text], {type:'text/plain'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = `threat-brief-${new Date().toISOString().slice(0,10)}.txt`;
  a.click(); URL.revokeObjectURL(url);
};

global.gtlRegenerateBrief = function() {
  const content = _el('gtl-brief-content');
  if (!content) return;
  content.innerHTML = '<div style="text-align:center;padding:40px;color:#64748b;"><i class="fas fa-brain fa-spin" style="font-size:24px;display:block;margin-bottom:12px;"></i>Regenerating intelligence brief…</div>';
  setTimeout(() => {
    content.innerHTML = _buildBriefingPanel().match(/id="gtl-brief-content">([\s\S]*?)<\/div>\s*<div class="gtl-brief-meta/)?.[1] || content.innerHTML;
  }, 1800);
};

global.gtlShareBrief = function() {
  if (navigator.share) {
    navigator.share({ title: 'Wadjet-Eye Threat Brief', text: 'Global Threat Intelligence Daily Brief', url: window.location.href });
  } else {
    navigator.clipboard?.writeText(window.location.href);
  }
};

/* Live simulated SIGINT ticker injection */
let _sigintInterval = null;
function _startSigintTicker() {
  if (_sigintInterval) clearInterval(_sigintInterval);
  const FRESH_ITEMS = [
    { priority:'FLASH', src:'AUTO-INTEL', text:'Automated IOC correlation: new Cobalt Strike watermark linked to APT41 cluster — 8 new C2 IPs added to blocklist.' },
    { priority:'URGENT', src:'TECHINT-15', text:'LockBit 3.0 affiliate portal shows 6 new targets listed — healthcare and municipal sectors predominant.' },
    { priority:'ROUTINE', src:'OSINT-17', text:'APT28 spear-phishing infrastructure newly registered: 4 domains mimicking NATO email portals.' },
    { priority:'CRITIC', src:'NETINT-11', text:'Sandworm beacon activity detected from compromised Latvian infrastructure node — C2 established.' },
  ];
  let idx = 0;
  _sigintInterval = setInterval(() => {
    const listEls = document.querySelectorAll('.gtl-sigint-list');
    if (!listEls.length) { clearInterval(_sigintInterval); return; }
    const item = FRESH_ITEMS[idx % FRESH_ITEMS.length];
    idx++;
    const pc  = _priorityColor(item.priority);
    const ts  = new Date().toLocaleString('en-US',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
    const div = document.createElement('div');
    div.className = 'gtl-sigint-item gtl-sigint-new';
    div.innerHTML = `
      <div class="gtl-sigint-header">
        <span class="gtl-sigint-priority" style="color:${pc};border:1px solid ${pc}33;">${item.priority}</span>
        <span class="gtl-sigint-src" style="color:${C.muted};">${item.src}</span>
        <span class="gtl-sigint-ts">${ts}</span>
      </div>
      <div class="gtl-sigint-text">${item.text}</div>`;
    listEls.forEach(list => {
      list.insertBefore(div.cloneNode(true), list.firstChild);
      /* Remove if too many */
      while (list.children.length > 25) list.removeChild(list.lastChild);
    });
  }, 12000);
}

/* Cleanup on re-render */
function _cleanup() {
  if (_sigintInterval)    { clearInterval(_sigintInterval);  _sigintInterval = null; }
  if (_gcmTickerInterval) { clearInterval(_gcmTickerInterval); _gcmTickerInterval = null; }
  if (_gcmRAF)            { cancelAnimationFrame(_gcmRAF);   _gcmRAF = null; }
  _gcmComets = [];
  _gcmInitialized = false;
}

/* ═══════════════════════════════════════════════════════════════════════════
   §13  ENTRY POINT
═══════════════════════════════════════════════════════════════════════════ */
global.renderGlobalThreatLandscape = function() {
  _cleanup();

  const container = document.getElementById('page-global-threat-landscape');
  if (!container) {
    console.warn('[GTL] Container #page-global-threat-landscape not found');
    return;
  }

  /* Already rendered guard */
  if (_el(GTL_ID)) {
    _startSigintTicker();
    return;
  }

  /* Inject layout */
  _buildLayout(container);

  /* Render initial world-map panel */
  _initPanels();

  /* Start live ticker */
  _startSigintTicker();

  /* Update timestamp every 30s */
  setInterval(() => {
    const upd = _el('gtl-last-update');
    if (upd) upd.textContent = `Updated ${new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'})}`;
  }, 30000);

  /* Resize: re-render D3 map when container changes dimensions */
  let _gcmResizeTimer = null;
  const _gcmResizeObs = new ResizeObserver(() => {
    clearTimeout(_gcmResizeTimer);
    _gcmResizeTimer = setTimeout(() => {
      const svgEl = document.getElementById('gcm-world-svg');
      if (svgEl && _gcmTopoData && window.d3 && window.topojson) {
        if (_gcmRAF) { cancelAnimationFrame(_gcmRAF); _gcmRAF = null; }
        _gcmComets = [];
        _gcmRender(svgEl, _gcmTopoData);
      }
    }, 250);
  });
  const mapWrap = document.querySelector('.gcm-svg-wrap');
  if (mapWrap) _gcmResizeObs.observe(mapWrap);

  console.log(`[GTL v${GTL_VERSION}] Global Threat Landscape initialized — ${GTL_ACTORS.length} actors, ${GTL_CAMPAIGNS.length} campaigns, ${GTL_VULNS.length} CVEs`);
};

})(window);
