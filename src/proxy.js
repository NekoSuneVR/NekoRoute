import http from 'node:http';
import https from 'node:https';
import { HttpProxyAgent } from 'http-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';

export function makeAgent(proxy, targetProtocol = 'https:') {
  if (proxy.protocol === 'socks4' || proxy.protocol === 'socks5') {
    return new SocksProxyAgent(proxy.url);
  }
  return targetProtocol === 'http:'
    ? new HttpProxyAgent(proxy.url)
    : new HttpsProxyAgent(proxy.url);
}

export function requestViaProxy(proxy, targetUrl, { timeoutMs = 7000, maxBytes = 65536 } = {}) {
  const target = targetUrl instanceof URL ? targetUrl : new URL(targetUrl);
  const lib = target.protocol === 'http:' ? http : https;
  const agent = makeAgent(proxy, target.protocol);
  const started = Date.now();

  return new Promise((resolve, reject) => {
    const req = lib.get(target, {
      agent,
      timeout: timeoutMs,
      headers: {
        'user-agent': 'NekoRoute/0.1 (+health-check)',
        accept: 'application/json,text/plain,text/html;q=0.8,*/*;q=0.5'
      }
    }, res => {
      let bytes = 0;
      const chunks = [];
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes <= maxBytes) chunks.push(chunk);
        if (bytes > maxBytes) req.destroy(new Error('Response exceeded byte limit'));
      });
      res.on('end', () => resolve({
        statusCode: res.statusCode || 0,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
        latencyMs: Date.now() - started
      }));
    });
    req.on('timeout', () => req.destroy(new Error('Proxy request timed out')));
    req.on('error', reject);
  });
}
