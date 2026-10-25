const assert = require('node:assert/strict');
const fs = require('node:fs');
const { chromium } = require('playwright');
const { checkIP } = require('../lib/check.cjs');
const base = process.env.MYIP_TEST_URL || 'http://127.0.0.1:4173';
const chrome = process.env.MYIP_CHROME || (process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : undefined);
const ready = page => page.waitForFunction(() => document.querySelector('#results').getAttribute('aria-busy') === 'false', { timeout: 35000 });
const submit = async (page, ip) => { await page.locator('#ip-input').fill(ip); await page.locator('#submit').click(); await ready(page); };
const checks = [];
(async () => {
  fs.mkdirSync('outputs', { recursive: true });
  const browser = await chromium.launch({ headless: true, ...(chrome ? { executablePath: chrome } : {}) });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1080 }, permissions: ['clipboard-read', 'clipboard-write'] });
    const page = await context.newPage();
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    // Deterministic UI checks use explicitly simulated upstream responses.
    let mode = 'normal';
    await page.route('https://api.ipify.org/**', route => route.fulfill({ json: { ip: '1.1.1.1' } }));
    await page.route('**/api/check?*', async route => {
      const ip = new URL(route.request().url()).searchParams.get('ip');
      if (mode === 'http-error') return route.fulfill({ status: 503, json: { error: '检测服务暂时不可用，请稍后重试' } });
      const fetcher = async url => ({ ok: true, json: async () => String(url).includes('proxycheck') ? mode === 'missing' ? { status: 'denied' } : { status: 'ok', [ip]: { network: { asn: 'AS13335', provider: 'Cloudflare, Inc.', type: 'Business' }, location: { country_name: 'Australia', city_name: 'Sydney' }, detections: { risk: 12, proxy: false, vpn: false, tor: false, hosting: false, anonymous: false, compromised: false, scraper: false } } } : { success: true, ip, country: 'Australia', city: 'Sydney', connection: { asn: 13335, isp: 'Cloudflare, Inc.' }, timezone: { id: 'Australia/Sydney' } } });
      const report = await checkIP(ip, fetcher);
      await route.fulfill({ json: { ...report, cached: false } });
    });
    await page.goto(base); await ready(page);
    assert.equal(await page.locator('#score').innerText(), '88');
    assert.equal(await page.locator('#result-ip').innerText(), '1.1.1.1');
    checks.push('automatic visitor lookup and report');
    await submit(page, '8.8.4.4');
    assert.equal(await page.locator('#result-ip').innerText(), '8.8.4.4');
    await page.locator('#copy-ip').click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), '8.8.4.4');
    checks.push('manual lookup and copy');
    await page.locator('#hide-ip').check();
    assert.equal(await page.locator('#result-ip').innerText(), '8.8.•••.•••');
    assert.equal(await page.locator('#ip-input').getAttribute('type'), 'password');
    assert.equal((await page.locator('#sources').innerText()).includes('8.8.4.4'), false);
    await page.locator('#hide-ip').uncheck();
    assert.equal(await page.locator('#result-ip').innerText(), '8.8.4.4');
    checks.push('hide and restore IP in result, sources and search input');
    await submit(page, '999.1.1.1'); assert.equal(await page.locator('#query-error').isVisible(), true);
    assert.equal(await page.locator('#result-ip').innerText(), '8.8.4.4');
    checks.push('invalid address rejected without changing the existing report');
    mode = 'missing'; await submit(page, '1.1.1.1');
    assert.equal(await page.locator('#score').innerText(), '—');
    assert.equal(await page.locator('#report-state').innerText(), '数据不足');
    assert.equal(await page.locator('#coverage').innerText(), '0');
    assert.equal(await page.locator('.signal-state.good').count(), 0);
    checks.push('missing risk data never renders a clean score or green flags');
    mode = 'http-error'; await submit(page, '1.0.0.1');
    assert.equal(await page.locator('#query-error').isVisible(), true);
    assert.equal(await page.locator('#report-state').innerText(), '查询未完成');
    assert.equal(await page.locator('#copy-ip').isDisabled(), true);
    checks.push('service failure clears the previous score and allows retry');
    mode = 'normal'; await submit(page, '2606:4700:4700::1111');
    assert.equal(await page.locator('#ip-version').innerText(), 'IPv6');
    assert.equal(await page.locator('#query-error').isVisible(), false);
    await page.waitForTimeout(450);
    for (const width of [320, 390, 768, 1024, 1440]) {
      await page.setViewportSize({ width, height: 950 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `overflow at ${width}`);
      await page.screenshot({ path: `outputs/verified-${width}.png`, fullPage: true });
    }
    checks.push('IPv6 and responsive layout at 320, 390, 768, 1024 and 1440 pixels');
    await page.getByText('机房 IP、VPN 就一定不安全吗？', { exact: true }).click();
    assert.equal(await page.locator('details').nth(1).getAttribute('open'), '');
    checks.push('expandable explanations');
    await page.route('**/*favicon.ico?*', route => route.abort());
    await page.locator('#check-connectivity').click();
    await page.waitForFunction(() => !document.querySelector('#check-connectivity').disabled);
    assert.equal(await page.locator('.connection-item span').filter({ hasText: '未能确认' }).count(), 4);
    checks.push('website check completes even when every image fails');
    assert.deepEqual(errors, []); checks.push('no browser execution errors');
    await context.close();
    if (process.argv.includes('--live')) {
      const live = await browser.newPage({ viewport: { width: 1440, height: 1080 } });
      await live.goto(base); await ready(live);
      assert.equal(await live.locator('#query-error').isVisible(), false);
      await submit(live, '1.1.1.1');
      assert.equal(await live.locator('#result-ip').innerText(), '1.1.1.1');
      assert.equal(await live.locator('#query-error').isVisible(), false);
      assert.notEqual(await live.locator('#score').innerText(), '—', 'live upstream must supply an actual score');
      await live.waitForTimeout(450);
      await live.screenshot({ path: 'outputs/live-desktop.png', fullPage: true });
      // A fresh mobile page avoids compositor artifacts when full-page capture follows a desktop resize.
      const mobile = await browser.newPage({ viewport: { width: 390, height: 844 }, isMobile: true });
      await mobile.goto(base); await ready(mobile); await submit(mobile, '1.1.1.1');
      await mobile.waitForTimeout(450);
      assert.equal(await mobile.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      await mobile.screenshot({ path: 'outputs/live-mobile.png', fullPage: true });
      checks.push('REAL upstream: current visitor and manual public IP both return an actual risk score');
    }
    console.log(checks.map((name, i) => `${i + 1}. PASS ${name}`).join('\n'));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
