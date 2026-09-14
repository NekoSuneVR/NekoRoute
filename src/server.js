import express from 'express';
import helmet from 'helmet';
import http from 'node:http';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as cheerio from 'cheerio';
import pLimit from 'p-limit';
import { ProxyPool } from './pool.js';
import { validateTarget } from './security.js';
import { requestViaProxy } from './proxy.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const int = (name, fallback) => Number.parseInt(process.env[name] || String(fallback), 10);
const allowedHosts = (process.env.ALLOWED_TEST_HOSTS || 'example.com')
  .split(',').map(x => x.trim().toLowerCase()).filter(Boolean);

const config = {
  port: int('PORT', 3210),
  adminToken: process.env.ADMIN_TOKEN || '',
  sourceRefreshMs: int('SOURCE_REFRESH_MS', 300000),
  healthIntervalMs: int('HEALTHCHECK_INTERVAL_MS', 60000),
  healthTimeoutMs: int('HEALTHCHECK_TIMEOUT_MS', 7000),
  healthBatchSize: int('HEALTHCHECK_BATCH_SIZE', 80),
  maxProxies: int('MAX_PROXIES', 1500),
  healthcheckUrl: process.env.HEALTHCHECK_URL || 'https://api.ipify.org?format=json',
  exposeAddresses: String(process.env.EXPOSE_NODE_ADDRESSES || 'false').toLowerCase() === 'true',
  maxTestBytes: int('MAX_TEST_RESPONSE_BYTES', 262144),
  testTimeoutMs: int('TEST_TIMEOUT_MS', 10000),
  matrixMaxNodes: Math.max(1, Math.min(30, int('TEST_MATRIX_MAX_NODES', 20))),
  matrixConcurrency: Math.max(1, Math.min(10, int('TEST_MATRIX_CONCURRENCY', 4))),
  previewSessionTtlMs: Math.max(60000, int('PREVIEW_SESSION_TTL_MS', 900000)),
  previewMaxHtmlBytes: Math.max(65536, int('PREVIEW_MAX_HTML_BYTES', 2097152)),
  previewMaxResourceBytes: Math.max(65536, int('PREVIEW_MAX_RESOURCE_BYTES', 4194304))
};

const pool = new ProxyPool(config);
await pool.loadState();

const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(root, 'public'), { maxAge: '1h', etag: true }));

const nodeRef = node => createHash('sha256').update(node.id).digest('hex').slice(0, 24);
const findNodeByRef = ref => [...pool.nodes.values()].find(node => nodeRef(node) === ref) || null;

const safeNode = node => {
  const base = {
    ref: nodeRef(node),
    protocol: node.protocol,
    country: node.country,
    city: node.city,
    region: node.region,
    anonymity: node.anonymity,
    status: node.status,
    latencyMs: node.latencyMs,
    lastCheck: node.lastCheck,
    lastSuccess: node.lastSuccess,
    reliability: (node.successes || 0) + (node.failures || 0)
      ? Math.round(((node.successes || 0) / ((node.successes || 0)+(node.failures || 0))) * 100)
      : null
  };
  base.address = config.exposeAddresses ? `${node.ip}:${node.port}` : `hidden:${node.port}`;
  return base;
};

const selectorFromBody = body => ({
  country: body?.country ? String(body.country).toUpperCase() : undefined,
  region: body?.region ? String(body.region) : undefined,
  protocol: body?.protocol ? String(body.protocol).toLowerCase() : undefined
});

app.get('/api/health', (_req,res) => res.json({ ok: true, service: 'NekoRoute', nodes: pool.nodes.size }));
app.get('/api/stats', (_req,res) => res.json(pool.stats()));
app.get('/api/config', (_req,res) => res.json({
  allowedTestHosts: allowedHosts,
  exposeNodeAddresses: config.exposeAddresses,
  matrixMaxNodes: config.matrixMaxNodes,
  previewSessionTtlMs: config.previewSessionTtlMs
}));
app.get('/api/proxies', (req,res) => {
  const limit = Math.max(1, Math.min(500, Number(req.query.limit || 100)));
  const filters = {
    country: req.query.country ? String(req.query.country).toUpperCase() : undefined,
    region: req.query.region ? String(req.query.region) : undefined,
    protocol: req.query.protocol ? String(req.query.protocol).toLowerCase() : undefined,
    status: req.query.status ? String(req.query.status).toLowerCase() : undefined
  };
  res.json(pool.list(filters).slice(0, limit).map(safeNode));
});

function requireAdmin(req,res,next) {
  if (!config.adminToken || req.get('x-admin-token') !== config.adminToken) {
    return res.status(401).json({ error: 'Admin token required' });
  }
  next();
}

app.post('/api/admin/refresh', requireAdmin, async (_req,res,next) => {
  try { res.json(await pool.refreshSources()); } catch (e) { next(e); }
});
app.post('/api/admin/sweep', requireAdmin, async (_req,res,next) => {
  try { await pool.healthSweep(); res.json({ ok: true, stats: pool.stats() }); } catch (e) { next(e); }
});

app.post('/api/test-route', requireAdmin, async (req,res,next) => {
  try {
    const target = await validateTarget(req.body?.url, allowedHosts);
    const selector = selectorFromBody(req.body);
    let node = req.body?.nodeRef ? findNodeByRef(String(req.body.nodeRef)) : pool.select(selector);
    if (!node || node.status !== 'online') return res.status(503).json({ error: 'No healthy proxy matches that selection' });

    let lastError = null;
    for (let attempt = 0; attempt < 3 && node; attempt++) {
      try {
        const result = await requestViaProxy(node, target, { timeoutMs: config.testTimeoutMs, maxBytes: config.maxTestBytes });
        return res.json({
          ok: true,
          node: safeNode(node),
          target: target.toString(),
          statusCode: result.statusCode,
          statusText: http.STATUS_CODES[result.statusCode] || '',
          latencyMs: result.latencyMs,
          contentType: result.headers['content-type'] || null,
          location: result.headers.location || null,
          preview: result.body.slice(0, 6000)
        });
      } catch (error) {
        lastError = error;
        node.status = 'degraded';
        node.consecutiveFailures = (node.consecutiveFailures || 0) + 1;
        node = pool.list({ ...selector, status: 'online' }).find(n => n.id !== node?.id) || null;
      }
    }
    res.status(502).json({ error: lastError?.message || 'All matching routes failed' });
  } catch (e) { next(e); }
});

app.post('/api/test-matrix', requireAdmin, async (req,res,next) => {
  try {
    const target = await validateTarget(req.body?.url, allowedHosts);
    const selector = selectorFromBody(req.body);
    const requested = Math.max(1, Math.min(config.matrixMaxNodes, Number(req.body?.limit || 8)));
    let nodes = pool.list({ ...selector, status: 'online' });
    if (req.body?.nodeRef) {
      const exact = findNodeByRef(String(req.body.nodeRef));
      nodes = exact && exact.status === 'online' ? [exact] : [];
    }
    nodes = nodes.slice(0, requested);
    if (!nodes.length) return res.status(503).json({ error: 'No healthy proxies match that selection' });

    const limit = pLimit(config.matrixConcurrency);
    const started = Date.now();
    const results = await Promise.all(nodes.map(node => limit(async () => {
      try {
        const result = await requestViaProxy(node, target, {
          timeoutMs: config.testTimeoutMs,
          maxBytes: 8192,
          headersOnly: true
        });
        return {
          ok: true,
          node: safeNode(node),
          statusCode: result.statusCode,
          statusText: http.STATUS_CODES[result.statusCode] || '',
          latencyMs: result.latencyMs,
          location: result.headers.location || null,
          contentType: result.headers['content-type'] || null
        };
      } catch (error) {
        return { ok: false, node: safeNode(node), statusCode: null, statusText: '', latencyMs: null, error: String(error.message || error) };
      }
    })));

    const counts = {};
    for (const result of results) {
      const key = result.statusCode == null ? 'error' : String(result.statusCode);
      counts[key] = (counts[key] || 0) + 1;
    }
    res.json({
      ok: true,
      target: target.toString(),
      durationMs: Date.now() - started,
      tested: results.length,
      counts,
      results
    });
  } catch (e) { next(e); }
});

const previewSessions = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of previewSessions) {
    if (session.expiresAt <= now) previewSessions.delete(id);
  }
}, 60000).unref();

function previewSession(id) {
  const session = previewSessions.get(id);
  if (!session || session.expiresAt <= Date.now()) {
    if (session) previewSessions.delete(id);
    return null;
  }
  return session;
}

function absoluteUrl(value, base) {
  if (!value) return null;
  try {
    const url = new URL(value, base);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    return url.toString();
  } catch { return null; }
}

const previewPageUrl = (sessionId, url) => `/api/preview/${encodeURIComponent(sessionId)}?url=${encodeURIComponent(url)}`;
const previewResourceUrl = (sessionId, url) => `/api/preview-resource/${encodeURIComponent(sessionId)}?url=${encodeURIComponent(url)}`;

function rewriteCssUrls(css, sourceUrl, sessionId) {
  return String(css).replace(/url\(\s*(['"]?)([^'"\)]+)\1\s*\)/gi, (full, _quote, raw) => {
    if (/^(data:|blob:|#)/i.test(raw.trim())) return full;
    const abs = absoluteUrl(raw.trim(), sourceUrl);
    return abs ? `url("${previewResourceUrl(sessionId, abs)}")` : full;
  });
}

function rewriteHtml(html, sourceUrl, sessionId) {
  const $ = cheerio.load(html, { decodeEntities: false });
  $('script, iframe, frame, object, embed, portal').remove();
  $('meta[http-equiv]').each((_i, el) => {
    const value = String($(el).attr('http-equiv') || '').toLowerCase();
    if (value === 'content-security-policy' || value === 'refresh') $(el).remove();
  });
  $('base').remove();

  $('*').each((_i, el) => {
    for (const name of Object.keys(el.attribs || {})) {
      if (/^on/i.test(name)) $(el).removeAttr(name);
    }
  });

  $('a[href]').each((_i, el) => {
    const raw = $(el).attr('href');
    if (!raw || raw.startsWith('#')) return;
    const abs = absoluteUrl(raw, sourceUrl);
    if (!abs) {
      $(el).attr('href', '#').attr('data-neko-blocked', 'true');
      return;
    }
    $(el).attr('href', '#').attr('data-neko-url', abs);
  });

  const resourceAttrs = [
    ['img', 'src'], ['source', 'src'], ['video', 'poster'], ['audio', 'src'],
    ['link[rel="stylesheet"]', 'href'], ['link[rel="icon"]', 'href']
  ];
  for (const [selector, attr] of resourceAttrs) {
    $(selector).each((_i, el) => {
      const abs = absoluteUrl($(el).attr(attr), sourceUrl);
      if (abs) $(el).attr(attr, previewResourceUrl(sessionId, abs)).removeAttr('integrity').removeAttr('crossorigin');
    });
  }

  $('[srcset]').each((_i, el) => {
    const rewritten = String($(el).attr('srcset') || '').split(',').map(part => {
      const bits = part.trim().split(/\s+/);
      const abs = absoluteUrl(bits[0], sourceUrl);
      if (abs) bits[0] = previewResourceUrl(sessionId, abs);
      return bits.join(' ');
    }).join(', ');
    $(el).attr('srcset', rewritten);
  });

  $('[style]').each((_i, el) => {
    $(el).attr('style', rewriteCssUrls($(el).attr('style'), sourceUrl, sessionId));
  });
  $('style').each((_i, el) => {
    $(el).text(rewriteCssUrls($(el).html() || '', sourceUrl, sessionId));
  });

  $('form').attr('data-neko-form-disabled', 'true');
  $('form input, form textarea, form select, form button').attr('disabled', 'disabled');

  $('head').append(`
    <style>
      [data-neko-blocked="true"]{cursor:not-allowed!important;opacity:.55!important}
      [data-neko-form-disabled="true"]{outline:1px dashed rgba(34,197,94,.35)!important;outline-offset:3px!important}
    </style>`);
  $('body').prepend(`<div style="position:sticky;top:0;z-index:2147483647;padding:8px 12px;background:#07110b;color:#a7f3d0;border-bottom:1px solid #14532d;font:12px/1.4 system-ui,sans-serif">NekoRoute safe preview · scripts, forms, cookies and service workers are disabled · ${sourceUrl.replace(/&/g,'&amp;').replace(/</g,'&lt;')}</div>`);
  $('body').append(`<script>
    document.addEventListener('click', function (event) {
      var link = event.target && event.target.closest ? event.target.closest('a[data-neko-url]') : null;
      if (!link) return;
      event.preventDefault();
      parent.postMessage({ type: 'nekoroute-preview-nav', url: link.getAttribute('data-neko-url') }, '*');
    }, true);
    document.addEventListener('submit', function (event) { event.preventDefault(); }, true);
  </script>`);
  return $.html();
}

function previewErrorHtml(message) {
  const safe = String(message || 'Preview failed').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  return `<!doctype html><html><body style="margin:0;background:#050807;color:#e4e4e7;font:15px system-ui"><div style="max-width:760px;margin:64px auto;padding:24px;border:1px solid #27272a;border-radius:20px;background:#080d0a"><h1 style="color:#34d399">Preview blocked</h1><p>${safe}</p></div></body></html>`;
}

app.post('/api/preview-session', requireAdmin, async (req,res,next) => {
  try {
    const target = await validateTarget(req.body?.url, allowedHosts);
    const selector = selectorFromBody(req.body);
    const requestedNode = req.body?.nodeRef ? findNodeByRef(String(req.body.nodeRef)) : null;
    const node = requestedNode || pool.select(selector);
    if (!node || node.status !== 'online') return res.status(503).json({ error: 'No healthy proxy matches that selection' });
    const id = randomUUID();
    const expiresAt = Date.now() + config.previewSessionTtlMs;
    previewSessions.set(id, { id, nodeId: node.id, createdAt: Date.now(), expiresAt });
    res.json({
      ok: true,
      sessionId: id,
      expiresAt: new Date(expiresAt).toISOString(),
      url: target.toString(),
      frameUrl: previewPageUrl(id, target.toString()),
      node: safeNode(node)
    });
  } catch (e) { next(e); }
});

app.get('/api/preview/:sessionId', async (req,res) => {
  const session = previewSession(String(req.params.sessionId));
  if (!session) return res.status(410).type('html').send(previewErrorHtml('Preview session expired. Create a new session from the Preview page.'));
  const node = pool.nodes.get(session.nodeId);
  if (!node || node.status === 'offline') return res.status(503).type('html').send(previewErrorHtml('The selected proxy is no longer available.'));

  try {
    const target = await validateTarget(String(req.query.url || ''), allowedHosts);
    const result = await requestViaProxy(node, target, {
      timeoutMs: config.testTimeoutMs,
      maxBytes: config.previewMaxHtmlBytes,
      headers: { accept: 'text/html,application/xhtml+xml;q=0.9,text/plain;q=0.7,*/*;q=0.2' }
    });
    if (result.statusCode >= 300 && result.statusCode < 400 && result.headers.location) {
      const next = absoluteUrl(result.headers.location, target);
      if (next) {
        await validateTarget(next, allowedHosts);
        return res.redirect(302, previewPageUrl(session.id, next));
      }
    }
    const type = String(result.headers['content-type'] || 'text/html').toLowerCase();
    if (!type.includes('text/html') && !type.includes('application/xhtml+xml')) {
      return res.status(415).type('html').send(previewErrorHtml(`Preview only renders HTML. Upstream returned ${type}.`));
    }
    res.status(result.statusCode || 200);
    res.set('cache-control', 'no-store');
    res.set('content-type', 'text/html; charset=utf-8');
    res.send(rewriteHtml(result.body, target.toString(), session.id));
  } catch (error) {
    res.status(400).type('html').send(previewErrorHtml(error.message || error));
  }
});

app.get('/api/preview-resource/:sessionId', async (req,res) => {
  const session = previewSession(String(req.params.sessionId));
  if (!session) return res.status(410).end();
  const node = pool.nodes.get(session.nodeId);
  if (!node || node.status === 'offline') return res.status(503).end();
  try {
    const target = await validateTarget(String(req.query.url || ''), allowedHosts);
    const result = await requestViaProxy(node, target, {
      timeoutMs: config.testTimeoutMs,
      maxBytes: config.previewMaxResourceBytes,
      headers: { accept: '*/*' }
    });
    if (result.statusCode >= 300 && result.statusCode < 400 && result.headers.location) {
      const next = absoluteUrl(result.headers.location, target);
      if (next) {
        await validateTarget(next, allowedHosts);
        return res.redirect(302, previewResourceUrl(session.id, next));
      }
    }
    const type = String(result.headers['content-type'] || 'application/octet-stream').toLowerCase();
    const allowed = type.startsWith('image/') || type.startsWith('font/') || type.includes('text/css') ||
      type.includes('font-woff') || type.includes('application/vnd.ms-fontobject') || type.includes('application/octet-stream');
    if (!allowed) return res.status(415).end();
    res.status(result.statusCode || 200);
    res.set('cache-control', 'private, max-age=120');
    res.set('content-type', result.headers['content-type'] || 'application/octet-stream');
    if (type.includes('text/css')) {
      return res.send(rewriteCssUrls(result.body, target.toString(), session.id));
    }
    res.send(result.bodyBuffer);
  } catch {
    res.status(404).end();
  }
});

app.use((err,_req,res,_next) => {
  console.error(err);
  res.status(400).json({ error: err.message || 'Request failed' });
});

app.get('/tester', (_req,res) => res.sendFile(path.join(root, 'public', 'tester.html')));
app.get('/preview', (_req,res) => res.sendFile(path.join(root, 'public', 'preview.html')));
app.get('/{*splat}', (_req,res) => res.sendFile(path.join(root, 'public', 'index.html')));

const server = app.listen(config.port, '0.0.0.0', () => console.log(`[NekoRoute] listening on :${config.port}`));

let sourceBusy = false;
let sweepBusy = false;
const refresh = async () => {
  if (sourceBusy) return;
  sourceBusy = true;
  try {
    const r = await pool.refreshSources();
    console.log(`[sources] ${r.retained ? 'retained' : 'loaded'} ${r.count} proxies`);
    for (const stat of r.sourceStats || []) {
      if (stat.ok) {
        console.log(`[sources:${stat.source}] ${stat.count} proxies${stat.endpoint ? ` via ${stat.endpoint}` : ''}`);
        for (const failed of stat.fallbackErrors || []) console.warn(`[sources:${stat.source}] fallback failed ${failed.endpoint}: ${failed.error}`);
      } else {
        const detail = (stat.errors || []).map(x => `${x.endpoint}: ${x.error}`).join(' | ');
        console.error(`[sources:${stat.source}] failed${detail ? ` - ${detail}` : ''}`);
      }
    }
  } catch (e) { console.error('[sources]', e.message); }
  finally { sourceBusy = false; }
};
const sweep = async () => {
  if (sweepBusy) return;
  sweepBusy = true;
  try { await pool.healthSweep(); console.log('[health] sweep complete'); }
  catch (e) { console.error('[health]', e.message); }
  finally { sweepBusy = false; }
};

refresh().then(sweep);
setInterval(refresh, config.sourceRefreshMs).unref();
setInterval(sweep, config.healthIntervalMs).unref();
setInterval(() => pool.saveState(), 120000).unref();

for (const signal of ['SIGTERM','SIGINT']) {
  process.on(signal, async () => {
    await pool.saveState();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
  });
}
