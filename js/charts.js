/* ══════════════════════════════════════════════════════════
   ArgusWatch — Charts Module
   Chart.js and ECharts initializations
   ══════════════════════════════════════════════════════════ */

let timelineChartInst = null;
let iocDistChartInst = null;
let tpiGaugeInst = null;
let currentTimeRange = '7d';

/* ────────────────── TIMELINE CHART ────────────────── */
function initTimelineChart() {
  const ctx = document.getElementById('timelineChart');
  if (!ctx) return;

  const labels7d = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  const data7d = {
    critical: [2, 1, 4, 2, 3, 1, 3],
    high: [12, 8, 15, 10, 18, 6, 14],
    medium: [28, 22, 35, 18, 30, 15, 25],
    low: [45, 38, 52, 34, 48, 29, 41],
  };

  if (timelineChartInst) timelineChartInst.destroy();

  timelineChartInst = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels7d,
      datasets: [
        {
          label: 'Critical',
          data: data7d.critical,
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239,68,68,0.1)',
          fill: true,
          tension: 0.4,
          pointRadius: 3,
          borderWidth: 2,
        },
        {
          label: 'High',
          data: data7d.high,
          borderColor: '#f97316',
          backgroundColor: 'rgba(249,115,22,0.08)',
          fill: true,
          tension: 0.4,
          pointRadius: 3,
          borderWidth: 2,
        },
        {
          label: 'Medium',
          data: data7d.medium,
          borderColor: '#f59e0b',
          backgroundColor: 'rgba(245,158,11,0.06)',
          fill: true,
          tension: 0.4,
          pointRadius: 3,
          borderWidth: 2,
        },
        {
          label: 'Low',
          data: data7d.low,
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59,130,246,0.05)',
          fill: true,
          tension: 0.4,
          pointRadius: 3,
          borderWidth: 2,
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'top',
          labels: {
            color: '#94a3b8',
            font: { size: 11, family: 'Inter' },
            boxWidth: 10,
            padding: 12,
          }
        },
        tooltip: {
          mode: 'index',
          intersect: false,
          backgroundColor: '#111827',
          borderColor: '#1e2d45',
          borderWidth: 1,
          titleColor: '#e2e8f0',
          bodyColor: '#94a3b8',
          padding: 10,
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(30,45,69,0.6)', drawTicks: false },
          ticks: { color: '#64748b', font: { size: 10 } }
        },
        y: {
          grid: { color: 'rgba(30,45,69,0.6)', drawTicks: false },
          ticks: { color: '#64748b', font: { size: 10 } },
          beginAtZero: true,
        }
      },
      interaction: { mode: 'index', intersect: false },
    }
  });
}

function setTimeRange(btn, range) {
  document.querySelectorAll('.chart-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  currentTimeRange = range;

  const configs = {
    '7d': {
      labels: ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],
      data: { critical:[2,1,4,2,3,1,3], high:[12,8,15,10,18,6,14], medium:[28,22,35,18,30,15,25], low:[45,38,52,34,48,29,41] }
    },
    '30d': {
      labels: Array.from({length:30}, (_,i) => `D${i+1}`),
      data: {
        critical: Array.from({length:30}, () => Math.floor(Math.random()*6)+1),
        high: Array.from({length:30}, () => Math.floor(Math.random()*20)+5),
        medium: Array.from({length:30}, () => Math.floor(Math.random()*40)+15),
        low: Array.from({length:30}, () => Math.floor(Math.random()*60)+25),
      }
    },
    '90d': {
      labels: Array.from({length:13}, (_,i) => `W${i+1}`),
      data: {
        critical: Array.from({length:13}, () => Math.floor(Math.random()*30)+10),
        high: Array.from({length:13}, () => Math.floor(Math.random()*80)+40),
        medium: Array.from({length:13}, () => Math.floor(Math.random()*150)+80),
        low: Array.from({length:13}, () => Math.floor(Math.random()*250)+120),
      }
    }
  };

  const cfg = configs[range];
  if (timelineChartInst) {
    timelineChartInst.data.labels = cfg.labels;
    timelineChartInst.data.datasets[0].data = cfg.data.critical;
    timelineChartInst.data.datasets[1].data = cfg.data.high;
    timelineChartInst.data.datasets[2].data = cfg.data.medium;
    timelineChartInst.data.datasets[3].data = cfg.data.low;
    timelineChartInst.update('active');
  }
}

/* ────────────────── IOC DISTRIBUTION CHART ────────────────── */
function initIOCDistChart() {
  const ctx = document.getElementById('iocDistChart');
  if (!ctx) return;

  if (iocDistChartInst) iocDistChartInst.destroy();

  iocDistChartInst = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['API Keys', 'Credentials', 'Vulnerabilities', 'Network IOCs', 'Dark Web', 'Ransomware', 'Phishing', 'Other'],
      datasets: [{
        data: [23, 18, 15, 22, 8, 6, 12, 6],
        backgroundColor: [
          'rgba(34,211,238,0.8)',
          'rgba(239,68,68,0.8)',
          'rgba(249,115,22,0.8)',
          'rgba(59,130,246,0.8)',
          'rgba(236,72,153,0.8)',
          'rgba(168,85,247,0.8)',
          'rgba(245,158,11,0.8)',
          'rgba(100,116,139,0.8)',
        ],
        borderColor: '#111827',
        borderWidth: 2,
        hoverOffset: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#94a3b8',
            font: { size: 10, family: 'Inter' },
            boxWidth: 8,
            padding: 6,
          }
        },
        tooltip: {
          backgroundColor: '#111827',
          borderColor: '#1e2d45',
          borderWidth: 1,
          titleColor: '#e2e8f0',
          bodyColor: '#94a3b8',
          callbacks: {
            label: function(ctx) {
              return ` ${ctx.label}: ${ctx.parsed}%`;
            }
          }
        }
      }
    }
  });
}

/* ────────────────── TPI GAUGE ────────────────── */
function initTPIGauge() {
  const ctx = document.getElementById('tpiGauge');
  if (!ctx) return;

  if (tpiGaugeInst) tpiGaugeInst.destroy();

  const value = 74;
  const remaining = 100 - value;

  tpiGaugeInst = new Chart(ctx, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [value, remaining],
        backgroundColor: [
          createGradient(ctx),
          'rgba(26,34,52,0.8)',
        ],
        borderWidth: 0,
        circumference: 240,
        rotation: -120,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      cutout: '75%',
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false }
      },
      animation: {
        animateRotate: true,
        duration: 1000,
      }
    }
  });
}

function createGradient(ctx) {
  try {
    const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 200, 0);
    gradient.addColorStop(0, '#22c55e');
    gradient.addColorStop(0.5, '#f59e0b');
    gradient.addColorStop(1, '#ef4444');
    return gradient;
  } catch(e) {
    return '#f97316';
  }
}

/* ────────────────── MITRE HEATMAP ────────────────── */
function initMitreHeatmap() {
  const container = document.getElementById('mitreHeatmap');
  if (!container) return;

  const techniques = [
    {id:'T1566',name:'Phishing',sev:'critical'},
    {id:'T1078',name:'Valid Accounts',sev:'critical'},
    {id:'T1190',name:'Exploit Public-Facing App',sev:'critical'},
    {id:'T1486',name:'Data Encrypted',sev:'critical'},
    {id:'T1059',name:'Command Scripting',sev:'high'},
    {id:'T1021',name:'Remote Services',sev:'high'},
    {id:'T1055',name:'Process Injection',sev:'high'},
    {id:'T1036',name:'Masquerading',sev:'high'},
    {id:'T1027',name:'Obfuscated Files',sev:'high'},
    {id:'T1041',name:'Exfiltration over C2',sev:'high'},
    {id:'T1547',name:'Boot Autostart',sev:'medium'},
    {id:'T1552',name:'Unsecured Credentials',sev:'critical'},
    {id:'T1562',name:'Impair Defenses',sev:'medium'},
    {id:'T1070',name:'Indicator Removal',sev:'medium'},
    {id:'T1083',name:'File Discovery',sev:'low'},
    {id:'T1082',name:'System Info Discovery',sev:'low'},
    {id:'T1057',name:'Process Discovery',sev:'low'},
    {id:'T1033',name:'System Owner Discovery',sev:'low'},
    {id:'T1049',name:'Network Connections',sev:'low'},
    {id:'T1090',name:'Proxy',sev:'medium'},
    {id:'T1071',name:'App Layer Protocol',sev:'medium'},
    {id:'T1105',name:'Ingress Tool Transfer',sev:'medium'},
    {id:'T1195',name:'Supply Chain',sev:'high'},
    {id:'T1133',name:'External Remote Svcs',sev:'high'},
    {id:'T1530',name:'Cloud Storage Object',sev:'medium'},
    {id:'T1567',name:'Exfiltration to Cloud',sev:'medium'},
    {id:'T1619',name:'Cloud Storage Enum',sev:'medium'},
    {id:'T1539',name:'Steal Web Session',sev:'high'},
    {id:'T1550',name:'Use Alternate Auth',sev:'high'},
    {id:'T1098',name:'Account Manipulation',sev:'medium'},
    {id:'T1136',name:'Create Account',sev:'low'},
    {id:'T1087',name:'Account Discovery',sev:'low'},
    {id:'T1003',name:'OS Credential Dump',sev:'high'},
    {id:'T1040',name:'Network Sniffing',sev:'medium'},
    {id:'T1046',name:'Network Service Scan',sev:'low'},
    {id:'T1048',name:'Exfil Alt Protocol',sev:'medium'},
    {id:'T1204',name:'User Execution',sev:'medium'},
    {id:'T1566.001',name:'Spear Phishing Attach',sev:'high'},
    {id:'T1566.002',name:'Spear Phishing Link',sev:'high'},
    {id:'T1078.002',name:'Domain Accounts',sev:'critical'},
    {id:'T1552.001',name:'Credentials In Files',sev:'critical'},
    {id:'T1552.004',name:'Private Keys',sev:'critical'},
    {id:'T1059.001',name:'PowerShell',sev:'high'},
    {id:'T1021.002',name:'SMB/Windows Admin',sev:'high'},
    {id:'T1553.004',name:'Install Root Cert',sev:'medium'},
    {id:'T1583.001',name:'Register Domains',sev:'medium'},
    {id:'T1589.001',name:'Employee Names',sev:'medium'},
    {id:'T1598.003',name:'Spear Phishing Voice',sev:'high'},
    {id:'T1621',name:'MFA Request Gen',sev:'high'},
    {id:'T1490',name:'Inhibit System Recovery',sev:'high'},
  ];

  // Fill up to 99 with "none"
  while (techniques.length < 99) {
    techniques.push({id:`T${1600+techniques.length}`,name:'Covered Technique',sev:'none'});
  }

  container.innerHTML = '';
  techniques.forEach(t => {
    const cell = document.createElement('div');
    cell.className = `mitre-cell mitre-cell-${t.sev === 'none' ? 'low' : t.sev}`;
    cell.title = `${t.id}: ${t.name}`;
    cell.style.opacity = t.sev === 'none' ? '0.2' : '1';
    cell.addEventListener('click', () => {
      showToast(`${t.id}: ${t.name}`, 'info');
    });
    container.appendChild(cell);
  });
}

/* ────────────────── ANIMATE METRIC COUNTERS ────────────────── */
function animateCounters() {
  const targets = {
    'm-critical': 3,
    'm-high': 47,
    'm-findings': 247,
    'm-feeds': 47,
    'm-iocs': 18432,
    'm-ai': 96,
  };

  Object.entries(targets).forEach(([id, target]) => {
    const el = document.getElementById(id);
    if (!el) return;
    let current = 0;
    const increment = target / 40;
    const timer = setInterval(() => {
      current = Math.min(current + increment, target);
      el.textContent = Math.floor(current).toLocaleString();
      if (current >= target) clearInterval(timer);
    }, 30);
  });
}

/* ────────────────── INIT ALL CHARTS ────────────────── */
function initAllCharts() {
  setTimeout(() => {
    initTimelineChart();
    initIOCDistChart();
    initTPIGauge();
    initMitreHeatmap();
    animateCounters();
  }, 100);
}
