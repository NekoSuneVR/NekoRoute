import https from 'node:https';
import { regionForCountry } from './regions.js';

const SOURCE_TIMEOUT_MS = Math.max(5000, Number.parseInt(process.env.SOURCE_FETCH_TIMEOUT_MS || '25000', 10));
const MAX_SOURCE_BYTES = Math.max(1024 * 1024, Number.parseInt(process.env.MAX_SOURCE_BYTES || String(32 * 1024 * 1024), 10));

function normalizeCountry(value) {
  const v = String(value || 'XX').trim().toUpperCase();
  return /^[A-Z]{2}$/.test(v) ? v : 'XX';
}

function parseProxyUrl(value) {
  try {
    const u = new URL(String(value || ''));
    const protocol = u.protocol.replace(':', '').toLowerCase();
    const port = Number(u.port);
    if (!u.hostname || !port) return null;
    return { protocol, ip: u.hostname, port };
  } catch {
    return null;
  }
}

function score01(value, divisor = 1) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n / divisor));
}

const SOURCES = [
  {
    name: 'Proxifly',
    endpoints: [
      'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.json',
      'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json'
    ],
    parse(data) {
      if (!Array.isArray(data)) return [];
      return data.map(x => {
        const fromUrl = parseProxyUrl(x.proxy);
        return {
          protocol: String(x.protocol || fromUrl?.protocol || '').toLowerCase(),
          ip: x.ip || fromUrl?.ip,
          port: Number(x.port || fromUrl?.port),
          https: Boolean(x.https),
          anonymity: String(x.anonymity || 'unknown').toLowerCase(),
          sourceScore: score01(x.score),
          country: normalizeCountry(x.geolocation?.country),
          city: x.geolocation?.city || 'Unknown'
        };
      });
    }
  },
  {
    name: 'ProxyScrape',
    endpoints: [
      'https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.json',
      'https://raw.githubusercontent.com/proxyscrape/free-proxy-list/main/proxies/all/data.json'
    ],
    parse(data) {
      if (!Array.isArray(data)) return [];
      return data.map(x => ({
        protocol: String(x.protocol || '').toLowerCase(),
        ip: x.ip,
        port: Number(x.port),
        https: Boolean(x.ssl) || String(x.protocol || '').toLowerCase() === 'https',
        anonymity: String(x.anonymity || 'unknown').toLowerCase(),
        sourceScore: score01(x.uptime_percent, 100),
        country: normalizeCountry(x.country_code),
        city: x.city || 'Unknown'
      }));
    }
  },
  {
    name: 'Proxio',
    endpoints: [
      'https://raw.githubusercontent.com/proxio-io/proxy-list/main/all.json',
      'https://cdn.jsdelivr.net/gh/proxio-io/proxy-list@main/all.json'
    ],
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
            sourceScore: Number.isFinite(Number(x.reliability))
              ? score01(x.reliability, 100)
              : score01(x.uptime),
            country: normalizeCountry(x.country_code || x.countryCode || x.country),
            city: x.city || 'Unknown'
          });
        }
      }
      return out;
    }
  }
];

function downloadText(url, redirectsLeft = 4) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      family: 4,
      headers: {
        'user-agent': 'NekoRoute/0.3 (+https://github.com/NekoSuneVR/NekoRoute)',
        accept: 'application/json,text/plain;q=0.9,*/*;q=0.5',
        'accept-encoding': 'identity',
        'cache-control': 'no-cache'
      }
    }, res => {
      const status = res.statusCode || 0;
      if (status >= 300 && status < 400 && res.headers.location) {
        res.resume();
        if (redirectsLeft <= 0) return reject(new Error('too many redirects'));
        const redirected = new URL(res.headers.location, url).toString();
        return downloadText(redirected, redirectsLeft - 1).then(resolve, reject);
      }
      if (status < 200 || status >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${status}`));
      }

      let bytes = 0;
      const chunks = [];
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > MAX_SOURCE_BYTES) {
          req.destroy(new Error(`source exceeded ${MAX_SOURCE_BYTES} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });

    req.setTimeout(SOURCE_TIMEOUT_MS, () => req.destroy(new Error(`timeout after ${SOURCE_TIMEOUT_MS}ms`)));
    req.on('error', reject);
  });
}

function validProxy(p) {
  return ['http','https','socks4','socks5'].includes(p.protocol) &&
    typeof p.ip === 'string' && p.ip.length > 0 && p.ip.length <= 255 &&
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

async function loadSource(source) {
  const errors = [];
  for (const endpoint of source.endpoints) {
    try {
      const raw = await downloadText(endpoint);
      const data = JSON.parse(raw);
      const items = source.parse(data).filter(validProxy);
      if (!items.length) throw new Error('source parsed successfully but contained 0 valid proxies');
      return { items, endpoint, errors };
    } catch (error) {
      errors.push({ endpoint, error: String(error?.message || error).slice(0, 240) });
    }
  }
  return { items: [], endpoint: null, errors };
}

export async function fetchProxySources(maxProxies = 1500) {
  const all = [];
  const sourceStats = [];

  // Load sources independently so one slow/dead provider cannot block the others.
  const results = await Promise.all(SOURCES.map(async source => ({ source, result: await loadSource(source) })));
  for (const { source, result } of results) {
    if (result.items.length) {
      all.push(...result.items.map(item => ({ ...item, source: source.name })));
      sourceStats.push({
        source: source.name,
        ok: true,
        count: result.items.length,
        endpoint: result.endpoint,
        fallbackErrors: result.errors
      });
    } else {
      sourceStats.push({ source: source.name, ok: false, count: 0, errors: result.errors });
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
