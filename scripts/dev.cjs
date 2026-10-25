const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const handler = require('../api/check.js');
const root = path.resolve(__dirname, '../dist');
http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/api/check') {
    req.query = Object.fromEntries(url.searchParams);
    res.status = code => { res.statusCode = code; return res; };
    res.json = body => { res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(body)); };
    try { await handler(req, res); } catch { res.status(500).json({ error: '检测暂时不可用，请稍后再试' }); }
    return;
  }
  let file = path.resolve(root, '.' + decodeURIComponent(url.pathname));
  if (!file.startsWith(root + path.sep) && file !== root) { res.writeHead(403); return res.end(); }
  if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
  if (!fs.existsSync(file)) { res.writeHead(404); return res.end('Not found'); }
  res.setHeader('Content-Type', ({ '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' })[path.extname(file)] || 'application/octet-stream');
  fs.createReadStream(file).pipe(res);
}).listen(Number(process.env.PORT || 4173), '127.0.0.1', () => console.log(`Local: http://127.0.0.1:${process.env.PORT || 4173}`));
