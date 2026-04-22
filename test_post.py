#!/usr/bin/env python3
"""Quick batch test of POST endpoints"""
import urllib.request, json, sys

BASE='http://localhost:4000'

def t(name, path, body=None, check=None):
    try:
        data = json.dumps(body).encode() if body else None
        hdrs = {'Content-Type':'application/json'}
        req = urllib.request.Request(BASE+path, data=data, headers=hdrs, method='POST')
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.loads(r.read())
        ok = check(d) if check else True
        print(('PASS' if ok else 'FAIL')+' '+name)
        if not ok:
            print('  keys:', list(d.keys()))
    except Exception as e:
        print('FAIL '+name+' err='+str(e)[:80])

t('POST /ingest', '/api/raykan/ingest',
  body={'events':[{'EventID':4688,'Image':'cmd.exe','CommandLine':'whoami','ts':1000}]},
  check=lambda d: d.get('success')==True)

t('POST /hunt', '/api/raykan/hunt',
  body={'query':'detect lateral movement','timeRange':'24h'},
  check=lambda d: d.get('success')==True)

t('POST /hunt/nl', '/api/raykan/hunt/nl',
  body={'query':'find ransomware activity'},
  check=lambda d: d.get('success')==True)

t('POST /investigate', '/api/raykan/investigate',
  body={'artifact':'8.8.8.8','type':'ip'},
  check=lambda d: d.get('success')==True)

t('POST /rule/generate', '/api/raykan/rule/generate',
  body={'description':'Detect PowerShell downloading files','tactic':'execution'},
  check=lambda d: d.get('success')==True and 'rule' in d)

t('POST /rule/validate', '/api/raykan/rule/validate',
  body={'rule':{'title':'Test','detection':{'selection':{'EventID':4688},'condition':'selection'},'level':'medium'}},
  check=lambda d: d.get('success')==True or 'valid' in d)

t('POST /ioc/batch', '/api/raykan/ioc/batch',
  body={'iocs':['8.8.8.8','1.1.1.1']},
  check=lambda d: d.get('success')==True or 'results' in d)

print('POST tests done')
