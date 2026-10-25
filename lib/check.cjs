const { isIP } = require('node:net');

function normalizeIP(value) {
  return isIP(value) === 6 ? new URL(`http://[${value}]/`).hostname.slice(1, -1) : value;
}
function publicIP(value) {
  if (typeof value !== 'string' || !isIP(value)) return false;
  let ip = value.toLowerCase();
  if (isIP(ip) === 4) {
    const [a, b, c] = ip.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113));
  }
  // Only global unicast; exclude mapped, local, multicast and documentation space.
  const canonical = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
  const first = parseInt(canonical.split(':')[0], 16);
  return first >= 0x2000 && first <= 0x3fff &&
    !/^2001:(db8|[012]?):/i.test(canonical) && !/^2002:/i.test(canonical) && !/^3fff:/i.test(canonical);
}
const boolean = value => typeof value === 'boolean' ? value : null;
const flagNames = { proxy: '代理', vpn: 'VPN', tor: 'Tor', hosting: '机房', compromised: '受控设备', scraper: '自动采集', anonymous: '匿名网络' };
function normalizeProxy(body, ip) {
  if (!body || !['ok', 'warning'].includes(body.status) || !body[ip]) throw new Error('风险数据暂不可用或今日查询额度已用完');
  const item = body[ip];
  const d = item.detections || {};
  const risk = typeof d.risk === 'number' && Number.isFinite(d.risk) && d.risk >= 0 && d.risk <= 100 ? d.risk : null;
  return {
    name: 'proxycheck.io', status: 'ok', warning: body.status === 'warning' ? '数据源提示查询接近限制' : null,
    risk, flags: Object.fromEntries(Object.keys(flagNames).map(k => [k, boolean(d[k])])),
    confidence: typeof d.confidence === 'number' && d.confidence >= 0 && d.confidence <= 100 ? d.confidence : null,
    network: { asn: item.network?.asn, org: item.network?.provider, type: item.network?.type },
    location: { country: item.location?.country_name, region: item.location?.region_name, city: item.location?.city_name, timezone: item.location?.timezone },
    updated: item.last_updated || null
  };
}
function normalizeGeo(body, ip) {
  if (!body || body.success !== true || normalizeIP(body.ip || '') !== normalizeIP(ip)) throw new Error('位置数据暂不可用');
  return {
    name: 'ipwho.is', status: 'ok',
    network: { asn: body.connection?.asn ? `AS${body.connection.asn}` : null, org: body.connection?.isp || body.connection?.org, type: null },
    location: { country: body.country, region: body.region, city: body.city, timezone: body.timezone?.id }
  };
}
async function requestJSON(url, fetcher) {
  const response = await fetcher(url, { signal: AbortSignal.timeout(8500), headers: { Accept: 'application/json' } });
  if (!response.ok) throw new Error(response.status === 429 ? '今日查询额度已用完，请稍后再试' : '数据源暂时无法连接');
  return response.json();
}
async function checkIP(ip, fetcher = fetch) {
  if (!publicIP(ip)) throw new Error('请输入有效的公网 IPv4 或 IPv6 地址');
  ip = normalizeIP(ip);
  const proxyURL = new URL(`https://proxycheck.io/v3/${encodeURIComponent(ip)}`);
  if (process.env.PROXYCHECK_API_KEY) proxyURL.searchParams.set('key', process.env.PROXYCHECK_API_KEY);
  const jobs = [
    ['proxycheck.io', () => requestJSON(proxyURL, fetcher).then(d => normalizeProxy(d, ip))],
    ['ipwho.is', () => requestJSON(`https://ipwho.is/${encodeURIComponent(ip)}`, fetcher).then(d => normalizeGeo(d, ip))]
  ];
  const sources = await Promise.all(jobs.map(async ([name, job]) => {
    try { return await job(); } catch (error) {
      return { name, status: 'error', message: error.name === 'TimeoutError' ? '查询超时，请稍后重试' : /额度/.test(error.message) ? '今日查询额度已用完，请稍后再试' : '数据源暂不可用，请稍后重试' };
    }
  }));
  const riskSource = sources.find(s => s.name === 'proxycheck.io' && s.status === 'ok');
  const risk = riskSource?.risk ?? null;
  const flags = riskSource?.flags || Object.fromEntries(Object.keys(flagNames).map(k => [k, null]));
  const coverage = Object.values(flags).filter(v => v !== null).length;
  return {
    ip, checkedAt: new Date().toISOString(), score: risk === null ? null : 100 - risk, risk,
    level: risk === null ? 'unknown' : risk >= 66 ? 'high' : risk >= 34 ? 'medium' : 'low',
    flags, coverage, total: Object.keys(flagNames).length, confidence: riskSource?.confidence ?? null,
    network: sources.find(s => s.status === 'ok' && s.network?.org)?.network || null,
    location: sources.find(s => s.name === 'ipwho.is' && s.status === 'ok')?.location || riskSource?.location || null,
    sources,
    methodology: '参考纯净度 = 100 − proxycheck.io 风险值。数值越高，表示该数据源记录的风险越低；它不是网站通行保证，也不是通用信誉认证。位置差异不参与评分。'
  };
}
module.exports = { publicIP, normalizeIP, normalizeProxy, normalizeGeo, checkIP, flagNames };
