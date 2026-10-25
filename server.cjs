const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const handler = require('./api/check.js');
const root = path.resolve(__dirname, 'dist');
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' };
function createServer() {
  return http.createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    let url, decoded;
    try { url = new URL(req.url, 'http://localhost'); decoded = decodeURIComponent(url.pathname); }
    catch { res.writeHead(400); return res.end('Bad request'); }
    if (url.pathname === '/healthz') {
      res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store');
      return res.end(JSON.stringify({ status: 'ok', service: 'myip' }));
    }
    if (url.pathname === '/api/check') {
      req.query = Object.fromEntries(url.searchParams);
      if (url.searchParams.getAll('ip').length !== 1) req.query.ip = '';
      // Only enable behind a reverse proxy that overwrites incoming forwarding headers.
      delete req.headers['x-vercel-forwarded-for'];
      if (process.env.TRUST_PROXY !== 'true') delete req.headers['x-forwarded-for'];
      res.status = code => { res.statusCode = code; return res; };
      res.json = body => { res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(body)); };
      try { await handler(req, res); } catch { res.status(500).json({ error: '检测暂时不可用，请稍后再试' }); }
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, { Allow: 'GET, HEAD' }); return res.end(); }
    let file = path.resolve(root, '.' + decoded);
    if (!file.startsWith(root + path.sep) && file !== root) { res.writeHead(403); return res.end(); }
    try {
      let stat = await fs.promises.stat(file);
      if (stat.isDirectory()) {
        if (!url.pathname.endsWith('/')) { res.writeHead(308, { Location: url.pathname + '/' + url.search }); return res.end(); }
        file = path.join(file, 'index.html'); stat = await fs.promises.stat(file);
      }
      if (!stat.isFile()) { res.writeHead(404); return res.end('Not found'); }
      res.setHeader('Content-Type', mime[path.extname(file)] || 'application/octet-stream');
      res.setHeader('Content-Length', stat.size);
      res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
      if (req.method === 'HEAD') return res.end();
      const stream = fs.createReadStream(file);
      stream.on('error', () => res.destroy()); stream.pipe(res);
    } catch { res.writeHead(404); res.end('Not found'); }
  });
}
if (require.main === module) {
  const host = process.env.HOST || '127.0.0.1'; const port = Number(process.env.PORT || 4173);
  const server = createServer(); server.requestTimeout = 25000; server.headersTimeout = 10000;
  server.listen(port, host, () => console.log(`MyIP: http://${host}:${port}`));
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => server.close(() => process.exit(0)));
}
module.exports = { createServer };
