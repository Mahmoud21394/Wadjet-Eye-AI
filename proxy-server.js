'use strict';

const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');
const url   = require('url');

const PORT = 3000;
const ROOT = __dirname;
const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

/* ───────────────── CORS ───────────────── */
function cors(res){
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type');
}

/* ───────────────── Static Server ───────────────── */
function serveStatic(req,res){
  let file = path.join(ROOT, req.url==='/'?'index.html':req.url);

  if(!file.startsWith(ROOT)){
    res.writeHead(403); return res.end('Forbidden');
  }

  if(!fs.existsSync(file)){
    file = path.join(ROOT,'index.html');
  }

  const data = fs.readFileSync(file);
  cors(res);
  res.writeHead(200);
  res.end(data);
}

/* ───────────────── NVD Proxy (ONLY THIS TALKS TO NVD) ───────────────── */
function handleNVD(req,res){
  const parsed = url.parse(req.url,true);
  const qs = new URLSearchParams(parsed.query).toString();
  const target = qs ? `${NVD_BASE}?${qs}` : NVD_BASE;

  console.log('[NVD PROXY]', target);

  const u = new URL(target);

  const options = {
    hostname: u.hostname,
    path: u.pathname + u.search,
    method: 'GET',
  };

  const pReq = https.request(options, pRes=>{
    let chunks=[];
    pRes.on('data',d=>chunks.push(d));
    pRes.on('end',()=>{
      cors(res);
      res.writeHead(200,{'Content-Type':'application/json'});
      res.end(Buffer.concat(chunks));
    });
  });

  pReq.on('error',e=>{
    cors(res);
    res.writeHead(500);
    res.end(JSON.stringify({error:e.message}));
  });

  pReq.end();
}

/* ───────────────── Server ───────────────── */
http.createServer((req,res)=>{
  if(req.url.startsWith('/proxy/nvd'))
    return handleNVD(req,res);

  return serveStatic(req,res);
}).listen(PORT,()=>{
  console.log(`Server running → http://localhost:${PORT}`);
});
