import express from 'express';
import helmet from 'helmet';
import http from 'node:http';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as cheerio from 'cheerio';
import pLimit from 'p-limit';
import { ProxyPool } from './pool.js';
import { validatePublicTarget } from './security.js';
import { requestViaProxy } from './proxy.js';
import { scanWebsite } from './scanner.js';
import { saveScanResult } from './database.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const int = (name, fallback) => Number.parseInt(process.env[name] || String(fallback), 10);
const config = {
  port: int('PORT', 3210), adminToken: process.env.ADMIN_TOKEN || '',
  sourceRefreshMs: int('SOURCE_REFRESH_MS', 300000), healthIntervalMs: int('HEALTHCHECK_INTERVAL_MS', 60000),
  healthTimeoutMs: int('HEALTHCHECK_TIMEOUT_MS', 7000), healthBatchSize: int('HEALTHCHECK_BATCH_SIZE', 80),
  maxProxies: int('MAX_PROXIES', 1500), healthcheckUrl: process.env.HEALTHCHECK_URL || 'https://api.ipify.org?format=json',
  exposeAddresses: String(process.env.EXPOSE_NODE_ADDRESSES || 'false').toLowerCase() === 'true',
  maxTestBytes: int('MAX_TEST_RESPONSE_BYTES', 262144), testTimeoutMs: int('TEST_TIMEOUT_MS', 10000),
  matrixMaxNodes: Math.max(1, Math.min(30, int('TEST_MATRIX_MAX_NODES', 20))),
  matrixConcurrency: Math.max(1, Math.min(10, int('TEST_MATRIX_CONCURRENCY', 4))),
  previewSessionTtlMs: Math.max(60000, int('PREVIEW_SESSION_TTL_MS', 900000)),
  previewMaxHtmlBytes: Math.max(65536, int('PREVIEW_MAX_HTML_BYTES', 2097152)),
  previewMaxResourceBytes: Math.max(65536, int('PREVIEW_MAX_RESOURCE_BYTES', 4194304)),
  publicRateLimitWindowMs: Math.max(10000, int('PUBLIC_RATE_LIMIT_WINDOW_MS', 60000)),
  publicRateLimitMax: Math.max(5, int('PUBLIC_RATE_LIMIT_MAX', 60)), scanRateLimitMax: Math.max(1, int('SCAN_RATE_LIMIT_MAX', 12)),
  scanTimeoutMs: Math.max(3000, int('SCAN_TIMEOUT_MS', 12000)), scanMaxBytes: Math.max(65536, int('SCAN_MAX_BYTES', 1048576)),
  virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY || '', googleWebRiskApiKey: process.env.GOOGLE_WEB_RISK_API_KEY || '',
  storeScanHistory: String(process.env.STORE_SCAN_HISTORY || 'false').toLowerCase() === 'true'
};

const pool = new ProxyPool(config);
await pool.loadState();
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', String(process.env.TRUST_PROXY || 'false').toLowerCase() === 'true' ? 1 : false);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(root, 'public'), { maxAge: '1h', etag: true }));

const nodeRef = node => createHash('sha256').update(node.id).digest('hex').slice(0, 24);
const findNodeByRef = ref => [...pool.nodes.values()].find(node => nodeRef(node) === ref) || null;
const safeNode = node => ({
  ref: nodeRef(node), protocol: node.protocol, country: node.country, city: node.city, region: node.region,
  anonymity: node.anonymity, status: node.status, latencyMs: node.latencyMs, lastCheck: node.lastCheck,
  lastSuccess: node.lastSuccess, address: config.exposeAddresses ? `${node.ip}:${node.port}` : `hidden:${node.port}`,
  reliability: (node.successes || 0) + (node.failures || 0) ? Math.round((node.successes || 0) / ((node.successes || 0)+(node.failures || 0)) * 100) : null
});
const selector = body => ({
  country: body?.country ? String(body.country).toUpperCase() : undefined,
  region: body?.region ? String(body.region) : undefined,
  protocol: body?.protocol ? String(body.protocol).toLowerCase() : undefined
});

const buckets = new Map();
const rateLimit = max => (req,res,next) => {
  max ||= config.publicRateLimitMax;
  const now = Date.now(), key = `${req.ip || req.socket.remoteAddress || 'unknown'}:${req.path}`;
  let b = buckets.get(key); if (!b || b.resetAt <= now) b = { count: 0, resetAt: now + config.publicRateLimitWindowMs };
  b.count++; buckets.set(key,b); res.set('x-ratelimit-limit', String(max)); res.set('x-ratelimit-remaining', String(Math.max(0,max-b.count)));
  if (b.count > max) return res.status(429).json({ error: 'Public rate limit exceeded. Try again shortly.' }); next();
};
setInterval(() => { const now=Date.now(); for (const [k,b] of buckets) if (b.resetAt <= now) buckets.delete(k); }, 60000).unref();
const requireAdmin = (req,res,next) => !config.adminToken || req.get('x-admin-token') !== config.adminToken ? res.status(401).json({ error:'Admin token required' }) : next();

app.get('/api/health', (_req,res) => res.json({ ok:true, service:'NekoRoute', nodes:pool.nodes.size }));
app.get('/api/stats', (_req,res) => res.json(pool.stats()));
app.get('/api/config', (_req,res) => res.json({
  exposeNodeAddresses: config.exposeAddresses, matrixMaxNodes: config.matrixMaxNodes,
  previewSessionTtlMs: config.previewSessionTtlMs, publicTools:true, previewAllowsAllPublicDomains:true,
  scannerProviders:{ virusTotal:Boolean(config.virusTotalApiKey), googleWebRisk:Boolean(config.googleWebRiskApiKey) },
  storeScanHistory: config.storeScanHistory,
  disclaimer:'NekoRoute is provided for regional availability, moderation, compatibility and defensive security analysis. Users are responsible for their use of the service and for complying with applicable laws and site terms.',
  privacyNotice:'Target website traffic is fetched through the selected proxy. NekoRoute does not guarantee anonymity or zero trace at the host, proxy, network-provider, or third-party reputation-provider layer.'
}));
app.get('/api/proxies', (req,res) => {
  const filters={ country:req.query.country?.toUpperCase(), region:req.query.region, protocol:req.query.protocol?.toLowerCase(), status:req.query.status?.toLowerCase() };
  res.json(pool.list(filters).slice(0,Math.max(1,Math.min(500,Number(req.query.limit||100)))).map(safeNode));
});
app.post('/api/admin/refresh', requireAdmin, async (_req,res,next) => { try { res.json(await pool.refreshSources()); } catch(e){next(e);} });
app.post('/api/admin/sweep', requireAdmin, async (_req,res,next) => { try { await pool.healthSweep(); res.json({ok:true,stats:pool.stats()}); } catch(e){next(e);} });

app.post('/api/test-route', rateLimit(), async (req,res,next) => {
  try {
    const target=await validatePublicTarget(req.body?.url), sel=selector(req.body);
    let node=req.body?.nodeRef?findNodeByRef(String(req.body.nodeRef)):pool.select(sel); if(!node||node.status!=='online') return res.status(503).json({error:'No healthy proxy matches that selection'});
    let lastError;
    for(let i=0;i<3&&node;i++) try {
      const r=await requestViaProxy(node,target,{timeoutMs:config.testTimeoutMs,maxBytes:config.maxTestBytes});
      return res.json({ok:true,node:safeNode(node),target:target.toString(),statusCode:r.statusCode,statusText:http.STATUS_CODES[r.statusCode]||'',latencyMs:r.latencyMs,contentType:r.headers['content-type']||null,location:r.headers.location||null,preview:r.body.slice(0,6000)});
    } catch(e){ lastError=e; node.status='degraded'; node.consecutiveFailures=(node.consecutiveFailures||0)+1; node=pool.list({...sel,status:'online'}).find(n=>n.id!==node?.id)||null; }
    res.status(502).json({error:lastError?.message||'All matching routes failed'});
  } catch(e){next(e);}
});

app.post('/api/test-matrix', rateLimit(), async (req,res,next) => {
  try {
    const target=await validatePublicTarget(req.body?.url), sel=selector(req.body), count=Math.max(1,Math.min(config.matrixMaxNodes,Number(req.body?.limit||8)));
    let nodes=pool.list({...sel,status:'online'}); if(req.body?.nodeRef){const n=findNodeByRef(String(req.body.nodeRef));nodes=n&&n.status==='online'?[n]:[];} nodes=nodes.slice(0,count);
    if(!nodes.length) return res.status(503).json({error:'No healthy proxies match that selection'});
    const limit=pLimit(config.matrixConcurrency), started=Date.now();
    const results=await Promise.all(nodes.map(node=>limit(async()=>{try{const r=await requestViaProxy(node,target,{timeoutMs:config.testTimeoutMs,maxBytes:8192,headersOnly:true});return{ok:true,node:safeNode(node),statusCode:r.statusCode,statusText:http.STATUS_CODES[r.statusCode]||'',latencyMs:r.latencyMs,location:r.headers.location||null,contentType:r.headers['content-type']||null};}catch(e){return{ok:false,node:safeNode(node),statusCode:null,statusText:'',latencyMs:null,error:String(e.message||e)};}})));
    const counts={}; for(const r of results){const k=r.statusCode==null?'error':String(r.statusCode);counts[k]=(counts[k]||0)+1;}
    res.json({ok:true,target:target.toString(),durationMs:Date.now()-started,tested:results.length,counts,results});
  } catch(e){next(e);}
});

app.post('/api/scan', rateLimit(config.scanRateLimitMax), async (req,res,next) => {
  try {
    const target=await validatePublicTarget(req.body?.url), requested=req.body?.nodeRef?findNodeByRef(String(req.body.nodeRef)):null, node=requested||pool.select(selector(req.body));
    if(!node||node.status!=='online') return res.status(503).json({error:'No healthy proxy matches that selection'});
    const report=await scanWebsite(node,target.toString(),config), output={ok:true,...report,node:safeNode(node),notice:'Heuristic and reputation results are indicators, not a guarantee that a site is safe or malicious.'};
    if (config.storeScanHistory) {
      saveScanResult({target:report.target,nodeId:node.id,country:node.country,verdict:report.verdict,score:report.score,statusCode:report.statusCode,findings:report.findings,providers:report.providers}).catch(e=>console.error('[scanner] persist:',e.message));
    }
    res.json(output);
  } catch(e){next(e);}
});

const sessions=new Map();
setInterval(()=>{const now=Date.now();for(const [id,s] of sessions)if(s.expiresAt<=now)sessions.delete(id);},60000).unref();
const getSession=id=>{const s=sessions.get(id);if(!s||s.expiresAt<=Date.now()){sessions.delete(id);return null;}return s;};
const absolute=(value,base)=>{try{const u=new URL(value,base);return ['http:','https:'].includes(u.protocol)?u.toString():null;}catch{return null;}};
const pageUrl=(id,url)=>`/api/preview/${encodeURIComponent(id)}?url=${encodeURIComponent(url)}`;
const resourceUrl=(id,url)=>`/api/preview-resource/${encodeURIComponent(id)}?url=${encodeURIComponent(url)}`;
const rewriteCss=(css,base,id)=>String(css).replace(/url\(\s*(['"]?)([^'"\)]+)\1\s*\)/gi,(m,_q,v)=>/^(data:|blob:|#)/i.test(v.trim())?m:(absolute(v.trim(),base)?`url("${resourceUrl(id,absolute(v.trim(),base))}")`:m));
function rewriteHtml(html,base,id){
  const $=cheerio.load(html,{decodeEntities:false}); $('script,iframe,frame,object,embed,portal').remove(); $('base').remove();
  $('meta[http-equiv]').each((_i,e)=>{const v=String($(e).attr('http-equiv')||'').toLowerCase();if(v==='content-security-policy'||v==='refresh')$(e).remove();});
  $('*').each((_i,e)=>{for(const n of Object.keys(e.attribs||{}))if(/^on/i.test(n))$(e).removeAttr(n);});
  $('a[href]').each((_i,e)=>{const raw=$(e).attr('href');if(!raw||raw.startsWith('#'))return;const u=absolute(raw,base);$(e).attr('href','#');if(u)$(e).attr('data-neko-url',u);else $(e).attr('data-neko-blocked','true');});
  for(const [sel,attr] of [['img','src'],['source','src'],['video','poster'],['audio','src'],['link[rel="stylesheet"]','href'],['link[rel="icon"]','href']]) $(sel).each((_i,e)=>{const u=absolute($(e).attr(attr),base);if(u)$(e).attr(attr,resourceUrl(id,u)).removeAttr('integrity').removeAttr('crossorigin');});
  $('[style]').each((_i,e)=>$(e).attr('style',rewriteCss($(e).attr('style'),base,id))); $('style').each((_i,e)=>$(e).text(rewriteCss($(e).html()||'',base,id)));
  $('form').attr('data-neko-form-disabled','true'); $('form input,form textarea,form select,form button').attr('disabled','disabled');
  $('body').prepend(`<div style="position:sticky;top:0;z-index:2147483647;padding:8px 12px;background:#07110b;color:#a7f3d0;border-bottom:1px solid #14532d;font:12px system-ui">NekoRoute safe preview · scripts/forms/cookies disabled</div>`);
  $('body').append(`<script>document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a[data-neko-url]');if(!a)return;e.preventDefault();parent.postMessage({type:'nekoroute-preview-nav',url:a.getAttribute('data-neko-url')},'*')},true);document.addEventListener('submit',function(e){e.preventDefault()},true)</script>`);
  return $.html();
}
const errorHtml=m=>`<!doctype html><html><body style="background:#050807;color:#e4e4e7;font:15px system-ui"><div style="max-width:760px;margin:64px auto;padding:24px;border:1px solid #27272a;border-radius:20px"><h1 style="color:#34d399">Preview blocked</h1><p>${String(m||'Preview failed').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}</p></div></body></html>`;

app.post('/api/preview-session', rateLimit(), async (req,res,next)=>{try{const target=await validatePublicTarget(req.body?.url),requested=req.body?.nodeRef?findNodeByRef(String(req.body.nodeRef)):null,node=requested||pool.select(selector(req.body));if(!node||node.status!=='online')return res.status(503).json({error:'No healthy proxy matches that selection'});const id=randomUUID(),expiresAt=Date.now()+config.previewSessionTtlMs;sessions.set(id,{nodeId:node.id,expiresAt});res.json({ok:true,sessionId:id,expiresAt:new Date(expiresAt).toISOString(),url:target.toString(),frameUrl:pageUrl(id,target.toString()),node:safeNode(node)});}catch(e){next(e);}});
app.get('/api/preview/:id',async(req,res)=>{const s=getSession(String(req.params.id));if(!s)return res.status(410).type('html').send(errorHtml('Preview session expired.'));const node=pool.nodes.get(s.nodeId);if(!node||node.status==='offline')return res.status(503).type('html').send(errorHtml('Selected proxy is unavailable.'));try{const target=await validatePublicTarget(String(req.query.url||'')),r=await requestViaProxy(node,target,{timeoutMs:config.testTimeoutMs,maxBytes:config.previewMaxHtmlBytes,headers:{accept:'text/html,application/xhtml+xml;q=0.9,text/plain;q=0.7,*/*;q=0.2'}});if(r.statusCode>=300&&r.statusCode<400&&r.headers.location){const next=absolute(r.headers.location,target);if(next){await validatePublicTarget(next);return res.redirect(302,pageUrl(req.params.id,next));}}const type=String(r.headers['content-type']||'text/html').toLowerCase();if(!type.includes('html'))return res.status(415).type('html').send(errorHtml(`Preview only renders HTML. Upstream returned ${type}.`));res.status(r.statusCode||200).set({'cache-control':'no-store','content-type':'text/html; charset=utf-8'}).send(rewriteHtml(r.body,target.toString(),req.params.id));}catch(e){res.status(400).type('html').send(errorHtml(e.message||e));}});
app.get('/api/preview-resource/:id',async(req,res)=>{const s=getSession(String(req.params.id));if(!s)return res.status(410).end();const node=pool.nodes.get(s.nodeId);if(!node||node.status==='offline')return res.status(503).end();try{const target=await validatePublicTarget(String(req.query.url||'')),r=await requestViaProxy(node,target,{timeoutMs:config.testTimeoutMs,maxBytes:config.previewMaxResourceBytes,headers:{accept:'*/*'}});if(r.statusCode>=300&&r.statusCode<400&&r.headers.location){const next=absolute(r.headers.location,target);if(next){await validatePublicTarget(next);return res.redirect(302,resourceUrl(req.params.id,next));}}const type=String(r.headers['content-type']||'application/octet-stream').toLowerCase(),allowed=type.startsWith('image/')||type.startsWith('font/')||type.includes('text/css')||type.includes('font-woff')||type.includes('application/octet-stream');if(!allowed)return res.status(415).end();res.status(r.statusCode||200).set({'cache-control':'private, max-age=120','content-type':r.headers['content-type']||'application/octet-stream'});return type.includes('text/css')?res.send(rewriteCss(r.body,target.toString(),req.params.id)):res.send(r.bodyBuffer);}catch{return res.status(404).end();}});

app.use((err,_req,res,_next)=>{console.error(err);res.status(400).json({error:err.message||'Request failed'});});
app.get('/tester',(_req,res)=>res.sendFile(path.join(root,'public','tester.html'))); app.get('/preview',(_req,res)=>res.sendFile(path.join(root,'public','preview.html'))); app.get('/scanner',(_req,res)=>res.sendFile(path.join(root,'public','scanner.html'))); app.get('/{*splat}',(_req,res)=>res.sendFile(path.join(root,'public','index.html')));
const server=app.listen(config.port,'0.0.0.0',()=>console.log(`[NekoRoute] listening on :${config.port}`));
let sourceBusy=false,sweepBusy=false;
const refresh=async()=>{if(sourceBusy)return;sourceBusy=true;try{const r=await pool.refreshSources();console.log(`[sources] ${r.retained?'retained':'loaded'} ${r.count} proxies (${r.discoveredThisRefresh??0} seen this refresh)`);for(const stat of r.sourceStats||[]){if(stat.ok)console.log(`[sources:${stat.source}] ${stat.count} proxies${stat.endpoint?` via ${stat.endpoint}`:''}`);else console.error(`[sources:${stat.source}] failed - ${(stat.errors||[]).map(x=>`${x.endpoint}: ${x.error}`).join(' | ')}`);}}catch(e){console.error('[sources]',e.message);}finally{sourceBusy=false;}};
const sweep=async()=>{if(sweepBusy)return;sweepBusy=true;try{await pool.healthSweep();console.log('[health] sweep complete');}catch(e){console.error('[health]',e.message);}finally{sweepBusy=false;}};
refresh().then(sweep);setInterval(refresh,config.sourceRefreshMs).unref();setInterval(sweep,config.healthIntervalMs).unref();setInterval(()=>pool.saveState(),120000).unref();
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,async()=>{await pool.saveState();server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),5000).unref();});
