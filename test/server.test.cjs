const test = require('node:test');
const assert = require('node:assert/strict');
const { createServer } = require('../server.cjs');
test('standalone server serves the app and API without an external hosting platform', async t => {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  let response = await fetch(base + '/');
  assert.equal(response.status, 200); assert.ok((await response.text()).includes('IP 纯净度检测'));
  response = await fetch(base + '/purity.css'); assert.equal(response.status, 200); assert.ok(response.headers.get('content-type').includes('text/css'));
  response = await fetch(base + '/healthz'); assert.deepEqual(await response.json(), { status: 'ok', service: 'myip' });
  response = await fetch(base + '/api/check?ip=127.0.0.1'); assert.equal(response.status, 400);
  response = await fetch(base + '/api/check?ip=8.8.8.8&ip=1.1.1.1'); assert.equal(response.status, 400);
  response = await fetch(base + '/api/check?ip=8.8.8.8', { method: 'POST' }); assert.equal(response.status, 405);
  response = await fetch(base + '/classic', { redirect: 'manual' }); assert.equal(response.status, 308); assert.equal(response.headers.get('location'), '/classic/');
  response = await fetch(base + '/classic/'); assert.equal(response.status, 200);
  response = await fetch(base + '/simple/'); assert.equal(response.status, 200);
  response = await fetch(base + '/server.cjs'); assert.equal(response.status, 404);
  response = await fetch(base + '/%2e%2e%2fpackage.json'); assert.equal(response.status, 403);
  response = await fetch(base + '/%E0%A4%A'); assert.equal(response.status, 400);
  response = await fetch(base + '/', { method: 'HEAD' }); assert.equal(response.status, 200); assert.equal(await response.text(), '');
  response = await fetch(base + '/', { method: 'POST' }); assert.equal(response.status, 405);
  response = await fetch(base + '/healthz'); assert.equal(response.status, 200);
});
test('tunnel mode uses the trusted visitor address rather than a spoofed forwarding header', async t => {
  const originalFetch = global.fetch;
  const previousTrust = process.env.TRUST_CLOUDFLARE_TUNNEL;
  process.env.TRUST_CLOUDFLARE_TUNNEL = 'true';
  global.fetch = async url => ({ ok: true, json: async () => String(url).includes('proxycheck') ? { status: 'ok', '1.0.0.1': { detections: { risk: 10 } } } : { success: true, ip: '1.0.0.1' } });
  const server = createServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    global.fetch = originalFetch;
    if (previousTrust === undefined) delete process.env.TRUST_CLOUDFLARE_TUNNEL; else process.env.TRUST_CLOUDFLARE_TUNNEL = previousTrust;
    await new Promise(resolve => server.close(resolve));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  let response;
  for (let i = 0; i < 21; i++) {
    response = await originalFetch(base + '/api/check?ip=1.0.0.1', { headers: { 'cf-connecting-ip': '198.51.100.3', 'x-forwarded-for': `spoof-${i}`, 'x-vercel-forwarded-for': `spoof-${i}` } });
    await response.text();
  }
  assert.equal(response.status, 429);
});
