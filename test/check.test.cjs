const test = require('node:test');
const assert = require('node:assert/strict');
const { publicIP, normalizeIP, normalizeProxy, checkIP } = require('../lib/check.cjs');
const handler = require('../api/check.js');
const ip = '8.8.8.8';
const flags = { proxy: false, vpn: false, tor: false, hosting: false, compromised: false, scraper: false, anonymous: false };
function proxy(risk = 10, detections = {}) { return { status: 'ok', [ip]: { detections: { ...flags, risk, ...detections }, network: { asn: 'AS15169', provider: 'Google LLC', type: 'Business' }, location: { country_name: 'United States', city_name: 'Mountain View' } } }; }
const geo = { ip, success: true, country: 'United States', city: 'San Jose', connection: { asn: 15169, isp: 'Google LLC' }, timezone: { id: 'America/Los_Angeles' } };
function fetcher(p, g = geo) { return async url => ({ ok: true, json: async () => String(url).includes('proxycheck') ? p : g }); }
function response() { return { headers: {}, setHeader(k, v) { this.headers[k] = v; }, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } }; }
test('public address validation rejects local, reserved, malformed and injection inputs', () => {
  for (const value of ['', 'localhost', 'https://example.com', '8.8.8.8/path', '8.8.8.8&key=x', '127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1', '169.254.1.1', '100.64.0.1', '198.18.0.1', '198.51.100.2', '203.0.113.1', '224.0.0.1', '0.0.0.0', '999.1.1.1', '::', '::1', '::ffff:127.0.0.1', 'fc00::1', 'fe80::1', '2001:db8::1', '2002:a00:1::', '3fff::1', ['8.8.8.8']]) assert.equal(publicIP(value), false, String(value));
  for (const value of [ip, '1.1.1.1', '192.0.1.1', '2606:4700:4700::1111', '2001:4860:4860::8888']) assert.equal(publicIP(value), true, value);
});
test('IPv6 normalization accepts equivalent provider spelling', () => assert.equal(normalizeIP('2606:4700:4700:0:0:0:0:1111'), '2606:4700:4700::1111'));
test('score uses the actual provider risk value and preserves differing locations', async () => {
  const data = await checkIP(ip, fetcher(proxy()));
  assert.equal(data.score, 90); assert.equal(data.level, 'low'); assert.equal(data.coverage, 7);
  assert.equal(data.location.city, 'San Jose'); assert.equal(data.sources[0].location.city, 'Mountain View');
});
test('high risk and positive flags remain visible', async () => {
  const data = await checkIP(ip, fetcher(proxy(95, { tor: true, proxy: true })));
  assert.equal(data.score, 5); assert.equal(data.level, 'high'); assert.equal(data.flags.tor, true);
});
test('missing, null, strings and out-of-range risk values never produce a clean score', async () => {
  for (const risk of [null, '0', -1, 101, NaN]) {
    const data = await checkIP(ip, fetcher(proxy(risk)));
    assert.equal(data.score, null, String(risk)); assert.equal(data.level, 'unknown');
  }
  const data = await checkIP(ip, fetcher({ status: 'ok', [ip]: {} }));
  assert.equal(data.score, null); assert.equal(data.coverage, 0);
  assert.equal(data.flags.proxy, null);
  assert.equal(normalizeProxy({ status: 'ok', [ip]: { detections: { proxy: 'false' } } }, ip).flags.proxy, null);
});
test('provider refusal preserves available geography and never claims safety', async () => {
  const data = await checkIP(ip, fetcher({ status: 'denied', message: 'quota reached' }));
  assert.equal(data.score, null); assert.equal(data.coverage, 0);
  assert.equal(data.sources[0].status, 'error'); assert.equal(data.sources[1].status, 'ok');
  assert.equal(data.network.org, 'Google LLC');
});
test('one failing geography source does not discard available risk data', async () => {
  const data = await checkIP(ip, fetcher(proxy(40), { success: false }));
  assert.equal(data.score, 60); assert.equal(data.level, 'medium'); assert.equal(data.sources[1].status, 'error');
});
test('complete outage returns unknown and does not leak internal errors or credentials', async () => {
  const data = await checkIP(ip, async () => { throw new Error('secret credential internal error'); });
  assert.equal(data.score, null); assert.equal(data.coverage, 0);
  assert.ok(data.sources.every(s => s.status === 'error'));
  assert.equal(JSON.stringify(data).includes('secret credential'), false);
});
test('timeouts and rate limits produce useful fallback information', async () => {
  const rate = await checkIP(ip, async () => ({ ok: false, status: 429 }));
  assert.ok(rate.sources.every(s => s.message.includes('额度')));
  const timeout = await checkIP(ip, async () => { throw new DOMException('Timed out', 'TimeoutError'); });
  assert.ok(timeout.sources.every(s => s.message.includes('超时')));
});
test('endpoint rejects non-GET and invalid input without calling upstream', async () => {
  let res = response(); await handler({ method: 'POST', query: {} }, res); assert.equal(res.statusCode, 405);
  for (const value of ['127.0.0.1', 'not-an-ip', ['8.8.8.8', '1.1.1.1']]) {
    res = response(); await handler({ method: 'GET', query: { ip: value } }, res); assert.equal(res.statusCode, 400);
  }
});
test('endpoint caches successful checks and enforces a local request limit', async () => {
  const previous = global.fetch; let calls = 0;
  global.fetch = async url => { calls++; return fetcher(proxy())(url); };
  try {
    const req = { method: 'GET', query: { ip }, headers: { 'x-forwarded-for': 'test-client' } };
    let res = response(); await handler(req, res); assert.equal(res.statusCode, 200); assert.equal(res.body.cached, false);
    res = response(); await handler(req, res); assert.equal(res.body.cached, true); assert.equal(calls, 2);
    for (let i = 0; i < 19; i++) { res = response(); await handler(req, res); }
    assert.equal(res.statusCode, 429); assert.ok(res.headers['Retry-After']);
    assert.equal(calls, 2);
  } finally { global.fetch = previous; }
});
