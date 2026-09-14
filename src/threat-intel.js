import fs from 'node:fs/promises';
import https from 'node:https';

const DEFAULT_FEED = 'https://openphish.com/feed.txt';
let state = {
  enabled: true,
  source: 'OpenPhish Community',
  sourceUrl: DEFAULT_FEED,
  lastRefresh: null,
  urls: new Set(),
  hosts: new Map(),
  error: null
};

function canonical(raw) {
  try {
    const u = new URL(String(raw || '').trim());
    if (!['http:', 'https:'].includes(u.protocol)) return null;
    u.hash = '';
    u.hostname = u.hostname.toLowerCase();
    if ((u.protocol === 'http:' && u.port === '80') || (u.protocol === 'https:' && u.port === '443')) u.port = '';
    return u.toString();
  } catch { return null; }
}

function hydrate(urls, lastRefresh = null) {
  const exact = new Set();
  const hosts = new Map();
  for (const raw of urls || []) {
    const url = canonical(raw);
    if (!url) continue;
    exact.add(url);
    try {
      const host = new URL(url).hostname;
      hosts.set(host, (hosts.get(host) || 0) + 1);
    } catch {}
  }
  state.urls = exact;
  state.hosts = hosts;
  state.lastRefresh = lastRefresh;
}

function downloadText(url, timeoutMs = 20000, maxBytes = 8 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      family: 4,
      headers: {
        'user-agent': 'NekoRoute/0.4 threat-feed-cache',
        accept: 'text/plain,*/*;q=0.2',
        'accept-encoding': 'identity'
      }
    }, res => {
      if ((res.statusCode || 0) >= 300 && (res.statusCode || 0) < 400 && res.headers.location) {
        res.resume();
        return downloadText(new URL(res.headers.location, url).toString(), timeoutMs, maxBytes).then(resolve, reject);
      }
      if ((res.statusCode || 0) < 200 || (res.statusCode || 0) >= 300) {
        res.resume();
        return reject(new Error(`feed HTTP ${res.statusCode || 0}`));
      }
      let bytes = 0;
      const chunks = [];
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > maxBytes) return req.destroy(new Error('threat feed too large'));
        chunks.push(chunk);
      });
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error('threat feed timeout')));
    req.on('error', reject);
  });
}

export async function initThreatIntel(config) {
  state.enabled = config.openPhishEnabled !== false;
  state.sourceUrl = config.openPhishFeedUrl || DEFAULT_FEED;
  if (!state.enabled) return status();
  try {
    const cached = JSON.parse(await fs.readFile(config.threatFeedCachePath, 'utf8'));
    hydrate(cached.urls || [], cached.lastRefresh || null);
  } catch {}
  const last = state.lastRefresh ? Date.parse(state.lastRefresh) : 0;
  if (!last || Date.now() - last >= config.threatFeedRefreshMs) {
    await refreshThreatIntel(config).catch(error => { state.error = String(error.message || error); });
  }
  return status();
}

export async function refreshThreatIntel(config) {
  if (config.openPhishEnabled === false) return status();
  const text = await downloadText(config.openPhishFeedUrl || DEFAULT_FEED);
  const urls = text.split(/\r?\n/).map(x => x.trim()).filter(x => x && !x.startsWith('#'));
  const now = new Date().toISOString();
  hydrate(urls, now);
  state.error = null;
  try {
    await fs.writeFile(config.threatFeedCachePath, JSON.stringify({ lastRefresh: now, urls: [...state.urls] }), 'utf8');
  } catch (error) {
    state.error = `cache write: ${error.message}`;
  }
  return status();
}

export function checkThreatIntel(rawUrl) {
  const url = canonical(rawUrl);
  if (!state.enabled || !url) return { enabled: state.enabled, exactMatch: false, hostMatches: 0, source: state.source, lastRefresh: state.lastRefresh };
  let host = '';
  try { host = new URL(url).hostname; } catch {}
  return {
    enabled: true,
    exactMatch: state.urls.has(url),
    hostMatches: Number(state.hosts.get(host) || 0),
    source: state.source,
    lastRefresh: state.lastRefresh,
    cachedUrls: state.urls.size
  };
}

export function status() {
  return {
    enabled: state.enabled,
    source: state.source,
    sourceUrl: state.sourceUrl,
    lastRefresh: state.lastRefresh,
    cachedUrls: state.urls.size,
    cachedHosts: state.hosts.size,
    error: state.error
  };
}
