#!/usr/bin/env python3
"""
Remove deprecated modules from Wadjet-Eye AI:
- Threat Actors
- CVE Intelligence Engine (exposure page)
- Threat Hunting Workspace
- Detection Engineering
- Sysmon Log Analyzer
- MITRE ATT&CK Navigator
"""

import re

# ═══════════════════════════════════════════════════════
#  index.html modifications
# ═══════════════════════════════════════════════════════
with open('/home/user/webapp/index.html', 'r', encoding='utf-8') as f:
    html = f.read()

# 1. Remove nav items
nav_remove = [
    # Threat Actors nav
    '''        <a href="#" class="nav-child" data-page="threat-actors">
          <i class="fas fa-user-secret"></i><span>Threat Actors</span>
        </a>
''',
    # CVE Intelligence Engine nav (exposure)
    '''        <a href="#" class="nav-child" data-page="exposure">
          <i class="fas fa-bug"></i><span>CVE Intelligence Engine</span>
          <span class="nav-child-badge" style="background:linear-gradient(90deg,#ef4444,#dc2626);color:#fff;font-size:8px;padding:1px 5px;border-radius:8px;">NVD</span>
        </a>
''',
    # Threat Hunting Workspace nav
    '''        <a href="#" class="nav-child" data-page="threat-hunting">
          <i class="fas fa-search"></i><span>Threat Hunting Workspace</span>
        </a>
''',
    # Detection Engineering nav
    '''        <a href="#" class="nav-child" data-page="detection-engineering">
          <i class="fas fa-code"></i><span>Detection Engineering</span>
        </a>
''',
    # Sysmon Log Analyzer nav
    '''        <a href="#" class="nav-child" data-page="sysmon">
          <i class="fas fa-file-code"></i><span>Sysmon Log Analyzer</span>
        </a>
''',
    # MITRE ATT&CK Navigator nav
    '''        <a href="#" class="nav-child" data-page="mitre-attack">
          <i class="fas fa-th"></i><span>MITRE ATT&amp;CK Navigator</span>
        </a>
''',
]

for item in nav_remove:
    if item in html:
        html = html.replace(item, '')
        print(f"  [OK] Removed nav item: {item[:60].strip()}")
    else:
        print(f"  [WARN] Nav item not found (may have whitespace diff): {item[:60].strip()}")

# 2. Remove page divs
page_remove = [
    # Threat Actors page
    (
        '\n    <!-- ======= THREAT ACTORS ======= -->\n    <div class="page" id="page-threat-actors">\n      <div id="threatActorsLiveContainer" style="padding:8px 0"></div>\n    </div>\n',
        ''
    ),
    # Sysmon page
    (
        '\n    <!-- ======= SYSMON ANALYZER ======= -->\n    <div class="page" id="page-sysmon">\n      <div id="sysmonWrap"></div>\n    </div>\n',
        ''
    ),
    # Threat Hunting page
    (
        '\n    <!-- ======= THREAT HUNTING ======= -->\n    <div class="page" id="page-threat-hunting">\n      <div id="threatHuntingWrap" style="min-height:400px"></div>\n    </div>\n',
        ''
    ),
    # Detection Engineering page
    (
        '\n    <!-- ======= DETECTION ENGINEERING ======= -->\n    <div class="page" id="page-detection-engineering">\n      <div id="detectionEngineeringWrap" style="min-height:400px"></div>\n    </div>\n',
        ''
    ),
    # MITRE ATT&CK Navigator page
    (
        '\n    <!-- ======= MITRE ATT&CK NAVIGATOR ======= -->\n    <div class="page" id="page-mitre-attack">\n      <div id="mitreCoverageLiveContainer" style="padding:8px 0"></div>\n      <div id="mitreAttackWrap"></div>\n    </div>\n',
        ''
    ),
]

for old, new in page_remove:
    if old in html:
        html = html.replace(old, new)
        print(f"  [OK] Removed page div: {old[:60].strip()}")
    else:
        print(f"  [WARN] Page div not found: {old[:60].strip()}")

# 3. Remove script tags
script_remove = [
    '<script src="js/sysmon.js"></script>\n',
    '<script src="js/threat-hunting.js"></script>\n',
    '<script src="js/detection-engineering.js"></script>\n',
    '<script src="js/mitre-navigator.js"></script>\n',
    '<script src="js/threat-actors-v2.js"></script>\n',
    '<script src="js/cve-intelligence.js"></script>\n',
]

for s in script_remove:
    if s in html:
        html = html.replace(s, '')
        print(f"  [OK] Removed script: {s.strip()}")
    else:
        print(f"  [WARN] Script tag not found: {s.strip()}")

# 4. Remove exposure page div (CVE Intelligence)
exposure_page = '\n    <!-- ======= EXPOSURE ======= -->\n    <div class="page" id="page-exposure">\n      <div id="exposureLiveContainer" style="padding:8px 0"></div>\n    </div>\n'
if exposure_page in html:
    html = html.replace(exposure_page, '')
    print("  [OK] Removed exposure/CVE page div")
else:
    print("  [WARN] Exposure page div not found")

with open('/home/user/webapp/index.html', 'w', encoding='utf-8') as f:
    f.write(html)
print("\n[index.html] Done.\n")

# ═══════════════════════════════════════════════════════
#  backend/server.js modifications
# ═══════════════════════════════════════════════════════
with open('/home/user/webapp/backend/server.js', 'r', encoding='utf-8') as f:
    srv = f.read()

# Remove imports
imports_remove = [
    "const sysmonRoutes      = require('./routes/sysmon');\n",
    "const threatActorRoutes   = require('./routes/threat-actors');\n",
    "const cveIntelRoutes      = require('./routes/cve-intelligence');\n",
    "const adversarySimRoutes  = require('./routes/adversary-sim');\n",
    "const threatGraphRoutes   = require('./routes/threat-graph');\n",
    "const whatifRoutes        = require('./routes/whatif');\n",
]

for imp in imports_remove:
    if imp in srv:
        srv = srv.replace(imp, '')
        print(f"  [OK] Removed server.js import: {imp.strip()}")
    else:
        print(f"  [WARN] Import not found: {imp.strip()}")

# Remove route registrations
routes_remove = [
    "app.use('/api/sysmon',          sysmonRoutes);\n",
    "app.use('/api/threat-actors',  threatActorRoutes);\n",
    "app.use('/api/cve',            cveIntelRoutes);\n",
    "app.use('/api/adversary-sim',  adversarySimRoutes);\n",
    "app.use('/api/threat-graph',   threatGraphRoutes);\n",
    "app.use('/api/whatif',         whatifRoutes);\n",
]

for route in routes_remove:
    if route in srv:
        srv = srv.replace(route, '')
        print(f"  [OK] Removed route registration: {route.strip()}")
    else:
        print(f"  [WARN] Route not found: {route.strip()}")

with open('/home/user/webapp/backend/server.js', 'w', encoding='utf-8') as f:
    f.write(srv)
print("\n[backend/server.js] Done.\n")

# ═══════════════════════════════════════════════════════
#  js/main.js modifications
# ═══════════════════════════════════════════════════════
with open('/home/user/webapp/js/main.js', 'r', encoding='utf-8') as f:
    mainjs = f.read()

# Remove page registry entries for deprecated modules
pages_to_remove = [
    "'threat-actors'",
    "'exposure'",
    "'sysmon'",
    "'threat-hunting'",
    "'detection-engineering'",
    "'mitre-attack'",
]

# We'll use regex to remove entire key: { ... }, entries
for page_key in pages_to_remove:
    # Match the key entry in the registry object
    pattern = r"  " + re.escape(page_key) + r":[^\n]*(?:\n(?!  '[a-z])[^\n]*)+"
    matches = re.findall(pattern, mainjs)
    if matches:
        for m in matches:
            mainjs = mainjs.replace(m, '', 1)
            print(f"  [OK] Removed page registry: {page_key}")
    else:
        # simpler line search
        print(f"  [INFO] Complex pattern for {page_key}, will use line replacement")

with open('/home/user/webapp/js/main.js', 'w', encoding='utf-8') as f:
    f.write(mainjs)
print("\n[js/main.js] Done.\n")

print("=== Module removal complete ===")
