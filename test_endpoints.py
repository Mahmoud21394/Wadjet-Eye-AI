#!/usr/bin/env python3
import urllib.request, json, time, sys

BASE = "http://localhost:4000"
PASS, FAIL = [], []

def test(name, method, path, body=None, check=None, timeout=25):
    url = BASE + path
    try:
        data = json.dumps(body).encode() if body else None
        headers = {"Content-Type": "application/json"} if body else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = json.loads(r.read())
        ok = check(resp) if check else True
        if ok:
            PASS.append(name)
            print(f"  PASS  {name}")
        else:
            FAIL.append(name)
            print(f"  FAIL  {name}  check={check.__doc__ or ''}")
            print(f"        resp keys: {list(resp.keys()) if isinstance(resp,dict) else type(resp)}")
    except Exception as e:
        FAIL.append(name)
        print(f"  FAIL  {name}  err={str(e)[:80]}")

# Health checks
test("/health",              "GET", "/health",              check=lambda d: d.get("status")=="OK")
test("/api/health",          "GET", "/api/health",          check=lambda d: d.get("status")=="OK")
test("/api/ping",            "GET", "/api/ping",            check=lambda d: d.get("ok")==True)

# RAYKAN endpoints
test("/api/raykan/health",   "GET", "/api/raykan/health",   check=lambda d: d.get("ok")==True)
test("/api/raykan/stats",    "GET", "/api/raykan/stats",    check=lambda d: d.get("stats",{}).get("rulesLoaded",0)>100 or d.get("success")==True)
test("/api/raykan/rules",    "GET", "/api/raykan/rules",    check=lambda d: len(d.get("rules",[]))>100)
test("/api/raykan/mitre",    "GET", "/api/raykan/mitre",    check=lambda d: d.get("coverage",{}).get("total",0)>100)
test("/api/raykan/ioc/8.8.8.8","GET","/api/raykan/ioc/8.8.8.8", check=lambda d: "ioc" in d or "value" in d or d.get("success")==True)

# RAYKAN POST endpoints
test("POST /api/raykan/ingest","POST","/api/raykan/ingest",
     body={"events":[{"EventID":4688,"Image":"cmd.exe","CommandLine":"whoami","ts":1000}]},
     check=lambda d: d.get("success")==True)

test("POST /api/raykan/hunt","POST","/api/raykan/hunt",
     body={"query":"detect lateral movement","timeRange":"24h"},
     check=lambda d: d.get("success")==True)

test("POST /api/raykan/hunt/nl","POST","/api/raykan/hunt/nl",
     body={"query":"find ransomware activity in the last 24 hours"},
     check=lambda d: d.get("success")==True)

test("POST /api/raykan/investigate","POST","/api/raykan/investigate",
     body={"artifact":"8.8.8.8","type":"ip"},
     check=lambda d: d.get("success")==True)

test("POST /api/raykan/rule/generate","POST","/api/raykan/rule/generate",
     body={"description":"Detect PowerShell downloading files","tactic":"execution"},
     check=lambda d: d.get("success")==True and "rule" in d)

test("POST /api/raykan/rule/validate","POST","/api/raykan/rule/validate",
     body={"rule":{"title":"Test Rule","detection":{"selection":{"EventID":4688},"condition":"selection"},"level":"medium"}},
     check=lambda d: d.get("success")==True or "valid" in d)

test("POST /api/raykan/analyze/sample","POST","/api/raykan/analyze/sample",
     body={"scenario":"ransomware"},
     check=lambda d: d.get("success")==True,
     timeout=30)

test("POST /api/raykan/ioc/batch","POST","/api/raykan/ioc/batch",
     body={"iocs":["8.8.8.8","1.1.1.1","malware.com"]},
     check=lambda d: d.get("success")==True or "results" in d)

# RBAC endpoints
test("/api/rbac/health",    "GET", "/api/rbac/health",    check=lambda d: d.get("status")=="operational")
test("/api/rbac/schema",    "GET", "/api/rbac/schema",    check=lambda d: d.get("status")=="operational")
test("/api/rbac/roles",     "GET", "/api/rbac/roles",     check=lambda d: len(d.get("roles",[]))>0)

# SOC endpoint
test("/api/soc/health",     "GET", "/api/soc/health",     check=lambda d: d.get("status") in ("ok","operational","healthy") or d.get("ok")==True)

print(f"\n{'='*50}")
print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print(f"FAILED: {', '.join(FAIL)}")
print(f"{'='*50}")
sys.exit(0 if not FAIL else 1)
