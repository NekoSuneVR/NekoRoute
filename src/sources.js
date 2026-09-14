import { regionForCountry } from './regions.js';

const SOURCES = [
  {
    name: 'Proxifly',
    url: 'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.json',
    parse(data) {
      if (!Array.isArray(data)) return [];
      return data.map(x => ({
        protocol: String(x.protocol || '').toLowerCase(),
        ip: x.ip,
        port: Number(x.port),
        https: Boolean(x.https),
        anonymity: x.anonymity || 'unknown',
        sourceScore: Number(x.score || 0),
        country: normalizeCountry(x.geolocation?.country),
        city: x.geolocation?.city || 'Unknown'
      }));
    }
  },
  {
    name: 'Proxio',
    url: 'https://raw.githubusercontent.com/proxio-io/proxy-list/main/all.json',
    parse(data) {
      const rows = Array.isArray(data) ? data : (Array.isArray(data?.proxies) ? data.proxies : []);
      const out = [];
      for (const x of rows) {
        const protocols = Array.isArray(x.protocols) ? x.protocols : [x.protocol || x.type].filter(Boolean);
        for (const protocolRaw of protocols) {
          const protocol = String(protocolRaw || '').toLowerCase();
          out.push({
            protocol,
            ip: x.ip || x.host,
            port: Number(x.port),
            https: protocol === 'https' || Boolean(x.ssl),
            anonymity: String(x.anonymity || 'unknown').toLowerCase(),
            sourceScore: Number.isFinite(Number(x.reliability)) ? Number(x.reliability) / 100 : Number(x.uptime || 0),
            country: normalizeCountry(x.country_code || x.countryCode || x.country),
            city: x.city || 'Unknown'
          });
        }
      }
      return out;
    }
  }
];

function normalizeCountry(value) {
  const v = String(value || 'XX').trim().toUpperCase();
  return /^[A-Z]{2}$/.test(v) ? v : 'XX';
}

function validProxy(p) {
  return ['http','https','socks4','socks5'].includes(p.protocol) &&
    typeof p.ip === 'string' && p.ip.length <= 64 &&
    Number.isInteger(p.port) && p.port > 0 && p.port < 65536;
}


function staticNodes() {
  const raw = String(process.env.STATIC_PROXY_NODES || '').trim();
  if (!raw) return [];
  const out = [];
  for (const entry of raw.split(';').map(x => x.trim()).filter(Boolean)) {
    const [rawUrl, rawCountry = 'XX', city = 'Static', source = 'Static'] = entry.split('|');
    try {
      const u = new URL(rawUrl);
      if (u.username || u.password) continue;
      const protocol = u.protocol.replace(':','').toLowerCase();
      const port = Number(u.port);
      const country = normalizeCountry(rawCountry);
      const item = {
        id: rawUrl,
        url: rawUrl,
        protocol,
        ip: u.hostname,
        port,
        https: protocol === 'https',
        anonymity: 'trusted',
        sourceScore: 1,
        country,
        city,
        source,
        region: regionForCountry(country),
        status: 'unknown',
        latencyMs: null,
        exitIp: null,
        successes: 0,
        failures: 0,
        consecutiveFailures: 0,
        lastCheck: null,
        lastSuccess: null
      };
      if (validProxy(item)) out.push(item);
    } catch {}
  }
  return out;
}

function diversityPick(items, max) {
  if (items.length <= max) return items;
  const buckets = new Map();
  for (const item of items) {
    const key = `${item.country}:${item.protocol}`;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(item);
  }
  const queues = [...buckets.values()];
  const result = [];
  let cursor = 0;
  while (result.length < max && queues.length) {
    const index = cursor % queues.length;
    const queue = queues[index];
    const item = queue.shift();
    if (item) result.push(item);
    if (!queue.length) queues.splice(index, 1);
    else cursor++;
  }
  return result;
}

export async function fetchProxySources(maxProxies = 1500) {
  const all = [];
  const sourceStats = [];
  for (const source of SOURCES) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 20000);
      const res = await fetch(source.url, { signal: controller.signal, headers: { 'user-agent': 'NekoRoute/0.1' } });
      clearTimeout(timer);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const items = source.parse(data).filter(validProxy);
      all.push(...items.map(item => ({ ...item, source: source.name })));
      sourceStats.push({ source: source.name, ok: true, count: items.length });
    } catch (error) {
      sourceStats.push({ source: source.name, ok: false, error: error.message });
    }
  }

  const merged = new Map();
  for (const item of all) {
    const url = `${item.protocol}://${item.ip}:${item.port}`;
    const existing = merged.get(url);
    if (!existing || item.sourceScore > existing.sourceScore) {
      merged.set(url, {
        id: url,
        url,
        ...item,
        region: regionForCountry(item.country),
        status: 'unknown',
        latencyMs: null,
        exitIp: null,
        successes: 0,
        failures: 0,
        consecutiveFailures: 0,
        lastCheck: null,
        lastSuccess: null
      });
    }
  }
  const statics = staticNodes();
  const staticIds = new Set(statics.map(x => x.id));
  const budget = Math.max(0, maxProxies - statics.length);
  const picked = diversityPick([...merged.values()].filter(x => !staticIds.has(x.id)), budget);
  sourceStats.push({ source: 'Static', ok: true, count: statics.length });
  return { proxies: [...statics, ...picked], sourceStats };
}
