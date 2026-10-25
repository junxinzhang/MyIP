const { publicIP, normalizeIP, checkIP } = require('../lib/check.cjs');
const cache = new Map();
const limits = new Map();
module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'GET') { res.setHeader('Allow', 'GET'); return res.status(405).json({ error: '请使用查询方式访问' }); }
  let ip = typeof req.query.ip === 'string' ? req.query.ip.trim() : '';
  if (!publicIP(ip)) return res.status(400).json({ error: '请输入有效的公网 IPv4 或 IPv6 地址，不支持内网或保留地址' });
  ip = normalizeIP(ip);
  const now = Date.now();
  const client = req.headers['x-vercel-forwarded-for'] || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'local';
  const limit = limits.get(client);
  if (limit && limit.until > now && limit.count >= 20) {
    res.setHeader('Retry-After', String(Math.ceil((limit.until - now) / 1000)));
    return res.status(429).json({ error: '查询太频繁，请一分钟后重试' });
  }
  limits.set(client, limit && limit.until > now ? { ...limit, count: limit.count + 1 } : { count: 1, until: now + 60000 });
  if (limits.size > 1000) for (const [key, value] of limits) if (value.until <= now || limits.size > 1000) limits.delete(key);
  const hit = cache.get(ip);
  if (hit && hit.until > now) return res.status(200).json({ ...hit.data, cached: true });
  const data = await checkIP(ip);
  if (cache.size >= 250) cache.delete(cache.keys().next().value);
  cache.set(ip, { until: now + (data.score === null ? 30000 : 600000), data });
  return res.status(200).json({ ...data, cached: false });
};
