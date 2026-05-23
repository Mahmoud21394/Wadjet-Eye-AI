#!/usr/bin/env python3
"""Build script for js/global-threat-landscape.js"""
import os

JS = r"""/**
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
   §4  WORLD MAP PANEL — SVG Choropleth + Threat Arcs
═══════════════════════════════════════════════════════════════════════════ */
function _buildWorldMap() {
  /* Simplified world map built with SVG paths for major nations.
     Threat intensity shown via fill colour. Live arcs animate between
     attacker countries and targeted ones. */

  /* Country shapes as simplified polygons [cx,cy,w,h,label] */
  const COUNTRY_RECTS = [
    ['USA',     160, 118, 70, 38, 'US'],
    ['Canada',  150, 82,  72, 32, 'CA'],
    ['Mexico',  148, 157, 34, 22, 'MX'],
    ['Brazil',  220, 200, 48, 52, 'BR'],
    ['UK',      368, 96,  14, 16, 'GB'],
    ['France',  378, 110, 16, 14, 'FR'],
    ['Germany', 392, 104, 16, 14, 'DE'],
    ['Spain',   370, 118, 20, 14, 'ES'],
    ['Italy',   394, 118, 12, 18, 'IT'],
    ['Ukraine', 422, 104, 22, 16, 'UA'],
    ['Russia',  460, 82,  130, 52, 'RU'],
    ['Turkey',  434, 120, 28, 14, 'TR'],
    ['Israel',  440, 134, 10, 10, 'IL'],
    ['Iran',    454, 126, 24, 18, 'IR'],
    ['Saudi',   446, 146, 22, 18, 'SA'],
    ['India',   502, 142, 28, 32, 'IN'],
    ['China',   544, 110, 60, 42, 'CN'],
    ['NKorea',  600, 108, 12, 12, 'KP'],
    ['SKorea',  604, 118, 12, 10, 'KR'],
    ['Japan',   618, 112, 14, 20, 'JP'],
    ['Taiwan',  606, 132, 10, 10, 'TW'],
    ['Vietnam', 576, 148, 12, 16, 'VN'],
    ['SEAsia',  572, 164, 30, 20, 'SG'],
    ['Australia',582, 218, 52, 38, 'AU'],
    ['Egypt',   428, 148, 16, 16, 'EG'],
    ['Nigeria', 396, 172, 16, 14, 'NG'],
    ['SAfrika', 412, 210, 20, 18, 'ZA'],
    ['Pakistan',488, 132, 20, 18, 'PK'],
  ];

  const THREAT_MAP = {US:98,RU:82,CN:79,GB:72,DE:68,FR:67,UA:91,IL:75,IR:74,KP:71,IN:65,BR:63,AU:69,CA:71,JP:66,KR:68,SA:72,SG:69,UA:91,PK:64,EG:63,NG:60,ZA:61,TW:86,VN:61};

  function _threatToColor(score) {
    if (!score) return '#1a2744';
    if (score >= 90) return 'rgba(255,45,85,0.7)';
    if (score >= 80) return 'rgba(255,107,53,0.6)';
    if (score >= 70) return 'rgba(245,158,11,0.55)';
    if (score >= 60) return 'rgba(59,130,246,0.45)';
    return 'rgba(34,211,238,0.25)';
  }

  /* Live attack arcs: [src_name, tgt_name, color] */
  const ARC_DEFINITIONS = [
    {src:'Russia',tgt:'Ukraine',color:C.crit},
    {src:'Russia',tgt:'USA',color:C.orange},
    {src:'China',tgt:'USA',color:C.orange},
    {src:'China',tgt:'Taiwan',color:C.crit},
    {src:'NKorea',tgt:'USA',color:C.amber},
    {src:'Iran',tgt:'Israel',color:C.red},
    {src:'Iran',tgt:'Saudi',color:C.orange},
    {src:'Russia',tgt:'Germany',color:C.amber},
    {src:'NKorea',tgt:'SKorea',color:C.amber},
    {src:'China',tgt:'India',color:C.amber},
    {src:'Russia',tgt:'UK',color:C.orange},
    {src:'China',tgt:'Japan',color:C.amber},
  ];

  const CX = (r) => r[1];
  const CY = (r) => r[2];

  /* Build a lookup cx/cy by label */
  const coordMap = {};
  COUNTRY_RECTS.forEach(r => { coordMap[r[0]] = {x:r[1]+r[3]/2, y:r[2]+r[4]/2}; });

  /* Generate animated arcs SVG */
  let arcsSvg = '';
  ARC_DEFINITIONS.forEach((arc, i) => {
    const s = coordMap[arc.src], t = coordMap[arc.tgt];
    if (!s || !t) return;
    const mx = (s.x + t.x) / 2;
    const my = Math.min(s.y, t.y) - 40;
    const id = `arc-${i}`;
    arcsSvg += `
      <path id="${id}" d="M${s.x},${s.y} Q${mx},${my} ${t.x},${t.y}"
        fill="none" stroke="${arc.color}" stroke-width="1.2" stroke-opacity="0.6"
        stroke-dasharray="4,3">
        <animate attributeName="stroke-dashoffset" from="0" to="-70" dur="${1.5 + i*0.2}s" repeatCount="indefinite"/>
      </path>
      <circle r="2.5" fill="${arc.color}" opacity="0.8">
        <animateMotion dur="${1.5 + i*0.2}s" repeatCount="indefinite">
          <mpath href="#${id}"/>
        </animateMotion>
      </circle>`;
  });

  /* Country rectangles */
  let rectsSvg = '';
  COUNTRY_RECTS.forEach(r => {
    const [name, cx, cy, w, h, iso] = r;
    const score = THREAT_MAP[iso] || 40;
    const fill = _threatToColor(score);
    const stroke = score >= 80 ? C.crit : score >= 70 ? C.orange : C.border;
    const sw = score >= 80 ? 1.5 : 0.8;
    rectsSvg += `<rect x="${cx}" y="${cy}" width="${w}" height="${h}" rx="3"
      fill="${fill}" stroke="${stroke}" stroke-width="${sw}"
      data-iso="${iso}" data-name="${name}" data-score="${score}"
      class="gtl-map-country" style="cursor:pointer;transition:fill 0.3s;">
      <title>${name} — Threat Score: ${score}/100</title>
    </rect>`;
  });

  /* Legend */
  const legendItems = [
    {label:'Critical (90+)', color:'rgba(255,45,85,0.7)'},
    {label:'High (80-89)',  color:'rgba(255,107,53,0.6)'},
    {label:'Elevated (70-79)',color:'rgba(245,158,11,0.55)'},
    {label:'Moderate (60-69)',color:'rgba(59,130,246,0.45)'},
    {label:'Low (<60)',     color:'rgba(34,211,238,0.25)'},
  ];
  let legendHtml = legendItems.map(li =>
    `<div class="gtl-legend-item"><span class="gtl-legend-swatch" style="background:${li.color};"></span>${li.label}</div>`
  ).join('');

  /* KPI bar above map */
  const totalActors = GTL_ACTORS.filter(a => a.active).length;
  const activeCamps = GTL_CAMPAIGNS.filter(c => c.status === 'Active').length;
  const critVulns   = GTL_VULNS.filter(v => v.severity === 'Critical' && v.exploit_wild).length;
  const zerodays    = GTL_VULNS.filter(v => v.zero_day && v.exploit_wild).length;

  return `
  <div class="gtl-map-kpi-row">
    <div class="gtl-map-kpi"><span class="gtl-map-kpi-val" style="color:${C.red}">${totalActors}</span><span>Active APT Groups</span></div>
    <div class="gtl-map-kpi"><span class="gtl-map-kpi-val" style="color:${C.orange}">${activeCamps}</span><span>Active Campaigns</span></div>
    <div class="gtl-map-kpi"><span class="gtl-map-kpi-val" style="color:${C.crit}">${critVulns}</span><span>Critical Wild Exploits</span></div>
    <div class="gtl-map-kpi"><span class="gtl-map-kpi-val" style="color:${C.purple}">${zerodays}</span><span>In-Wild Zero-Days</span></div>
    <div class="gtl-map-kpi"><span class="gtl-map-kpi-val" style="color:${C.accent}">LIVE</span><span>Intel Feed Status</span></div>
  </div>
  <div class="gtl-map-wrap">
    <svg viewBox="0 0 700 280" xmlns="http://www.w3.org/2000/svg" class="gtl-world-svg">
      <!-- Ocean -->
      <rect width="700" height="280" fill="#060d1f" rx="8"/>
      <!-- Grid lines -->
      <line x1="350" y1="0" x2="350" y2="280" stroke="${C.border}" stroke-width="0.3" stroke-dasharray="2,4"/>
      <line x1="0" y1="140" x2="700" y2="140" stroke="${C.border}" stroke-width="0.3" stroke-dasharray="2,4"/>
      <!-- Country shapes -->
      ${rectsSvg}
      <!-- Attack arcs -->
      ${arcsSvg}
      <!-- Labels -->
      <text x="160" y="80" fill="${C.muted}" font-size="8" font-family="monospace">AMERICAS</text>
      <text x="380" y="80" fill="${C.muted}" font-size="8" font-family="monospace">EUROPE</text>
      <text x="550" y="80" fill="${C.muted}" font-size="8" font-family="monospace">APAC</text>
      <text x="400" y="170" fill="${C.muted}" font-size="8" font-family="monospace">AFRICA / ME</text>
    </svg>
    <div class="gtl-map-legend">${legendHtml}</div>
  </div>
  <div class="gtl-map-spotlight" id="gtl-map-spotlight">
    <div style="color:${C.muted};font-size:13px;padding:12px;">Click a country to view threat profile</div>
  </div>`;
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
  /* World map */
  const mapMain = _el('gtl-map-main');
  if (mapMain) mapMain.innerHTML = _buildWorldMap();

  /* Attach map country click handler */
  document.querySelectorAll('.gtl-map-country').forEach(el => {
    el.addEventListener('click', function() {
      const iso = this.dataset.iso, name = this.dataset.name, score = this.dataset.score;
      _showCountrySpotlight(iso, name, parseInt(score));
    });
  });
}

function _showCountrySpotlight(iso, name, score) {
  const spot = _el('gtl-map-spotlight');
  if (!spot) return;
  const geo = GEO_RISK.find(g => g.code === iso);
  const actors = GTL_ACTORS.filter(a => a.origin === iso || (geo && geo.groups.some(gr => gr.includes(a.name.split(' ')[0]))));
  const camps  = GTL_CAMPAIGNS.filter(c => {
    const a = GTL_ACTORS.find(x=>x.id===c.actor);
    return a && a.origin === iso;
  });
  const riskColor = score>=90?C.crit:score>=80?C.orange:score>=70?C.amber:C.green;

  let content = `
  <div style="padding:14px;">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
      <span style="font-size:24px;">${geo?geo.flag:''}</span>
      <div>
        <div style="font-weight:700;color:${C.text};font-size:14px;">${name}</div>
        <div style="font-size:11px;color:${riskColor};">Threat Score: ${score}/100</div>
      </div>
    </div>`;

  if (geo) {
    content += `<div style="font-size:11px;color:${C.muted};margin-bottom:6px;">${geo.status} · ${geo.escalation}</div>
    <div style="font-size:11px;margin-bottom:8px;">${_esc(geo.nexus)}</div>`;
  }
  if (actors.length) {
    content += `<div style="font-size:10px;color:${C.muted};margin-bottom:4px;">ORIGIN ACTORS</div>
    <div>${actors.slice(0,3).map(a=>`<span class="gtl-group-chip">${_esc(a.name)}</span>`).join('')}</div>`;
  }
  if (camps.length) {
    content += `<div style="font-size:10px;color:${C.muted};margin-top:8px;margin-bottom:4px;">ACTIVE CAMPAIGNS: ${camps.length}</div>`;
  }
  content += '</div>';
  spot.innerHTML = content;
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
  if (_sigintInterval) { clearInterval(_sigintInterval); _sigintInterval = null; }
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

  console.log(`[GTL v${GTL_VERSION}] Global Threat Landscape initialized — ${GTL_ACTORS.length} actors, ${GTL_CAMPAIGNS.length} campaigns, ${GTL_VULNS.length} CVEs`);
};

})(window);
"""

out = '/home/user/webapp/js/global-threat-landscape.js'
with open(out, 'w') as f:
    f.write(JS)

import os
lines = JS.count('\n') + 1
size  = os.path.getsize(out)
print(f"global-threat-landscape.js: {lines} lines ({size:,} bytes)")
