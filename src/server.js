import express from 'express';
import helmet from 'helmet';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
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
  testTimeoutMs: int('TEST_TIMEOUT_MS', 10000)
};

const pool = new ProxyPool(config);
await pool.loadState();

const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(root, 'public'), { maxAge: '1h', etag: true }));

const safeNode = node => {
  const base = {
    id: node.id,
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
  if (config.exposeAddresses) base.address = `${node.ip}:${node.port}`;
  else base.address = `hidden:${node.port}`;
  return base;
};

app.get('/api/health', (_req,res) => res.json({ ok: true, service: 'NekoRoute', nodes: pool.nodes.size }));
app.get('/api/stats', (_req,res) => res.json(pool.stats()));
app.get('/api/config', (_req,res) => res.json({ allowedTestHosts: allowedHosts, exposeNodeAddresses: config.exposeAddresses }));
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
  if (!config.adminToken || req.get('x-admin-token') !== config.adminToken) return res.status(401).json({ error: 'Admin token required' });
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
    const selector = {
      country: req.body?.country ? String(req.body.country).toUpperCase() : undefined,
      region: req.body?.region || undefined,
      protocol: req.body?.protocol ? String(req.body.protocol).toLowerCase() : undefined
    };
    let node = pool.select(selector);
    if (!node) return res.status(503).json({ error: 'No healthy proxy matches that selection' });

    let lastError = null;
    for (let attempt = 0; attempt < 3 && node; attempt++) {
      try {
        const result = await requestViaProxy(node, target, { timeoutMs: config.testTimeoutMs, maxBytes: config.maxTestBytes });
        return res.json({
          ok: true,
          node: safeNode(node),
          target: target.origin + target.pathname,
          statusCode: result.statusCode,
          latencyMs: result.latencyMs,
          contentType: result.headers['content-type'] || null,
          preview: result.body.slice(0, 6000)
        });
      } catch (error) {
        lastError = error;
        node.status = 'degraded';
        node.consecutiveFailures = (node.consecutiveFailures || 0) + 1;
        node = pool.list(selector).find(n => n.status === 'online' && n.id !== node?.id) || null;
      }
    }
    res.status(502).json({ error: lastError?.message || 'All matching routes failed' });
  } catch (e) { next(e); }
});

app.use((err,_req,res,_next) => {
  console.error(err);
  res.status(400).json({ error: err.message || 'Request failed' });
});

app.get('/{*splat}', (_req,res) => res.sendFile(path.join(root, 'public', 'index.html')));

const server = app.listen(config.port, '0.0.0.0', () => console.log(`[NekoRoute] listening on :${config.port}`));

let sourceBusy = false;
let sweepBusy = false;
const refresh = async () => {
  if (sourceBusy) return;
  sourceBusy = true;
  try { const r=await pool.refreshSources(); console.log(`[sources] loaded ${r.count} proxies`); }
  catch (e) { console.error('[sources]', e.message); }
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
