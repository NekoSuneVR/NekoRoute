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
import { regionForCountry } from './regions.js';
import { initThreatIntel, refreshThreatIntel, status as threatIntelStatus } from './threat-intel.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const int = (name, fallback) => Number.parseInt(process.env[name] || String(fallback), 10);
const bool = (name, fallback = false) => String(process.env[name] ?? String(fallback)).toLowerCase() === 'true';
const displayNames = (() => { try { return new Intl.DisplayNames(['en'], { type:'region' }); } catch { return null; } })();
const normalizeCountry = code => String(code || 'XX').toUpperCase() === 'UK' ? 'GB' : String(code || 'XX').toUpperCase();
const countryName = code => { const c=normalizeCountry(code); if(c==='XX')return 'Unknown'; try{return displayNames?.of(c)||c;}catch{return c;} };

const config = {
  port:int('PORT',3210), adminToken:process.env.ADMIN_TOKEN||'', sourceRefreshMs:int('SOURCE_REFRESH_MS',300000), healthIntervalMs:int('HEALTHCHECK_INTERVAL_MS',60000),
  healthTimeoutMs:int('HEALTHCHECK_TIMEOUT_MS',7000), healthBatchSize:int('HEALTHCHECK_BATCH_SIZE',80), maxProxies:int('MAX_PROXIES',5000), healthcheckUrl:process.env.HEALTHCHECK_URL||'https://api.ipify.org?format=json',
  exposeAddresses:bool('EXPOSE_NODE_ADDRESSES'), maxTestBytes:int('MAX_TEST_RESPONSE_BYTES',262144), testTimeoutMs:int('TEST_TIMEOUT_MS',10000),
  matrixMaxNodes:Math.max(1,Math.min(30,int('TEST_MATRIX_MAX_NODES',20))), matrixConcurrency:Math.max(1,Math.min(10,int('TEST_MATRIX_CONCURRENCY',4))),
  previewSessionTtlMs:Math.max(60000,int('PREVIEW_SESSION_TTL_MS',900000)), previewTimeoutMs:Math.max(5000,int('PREVIEW_TIMEOUT_MS',45000)), previewMaxHtmlBytes:Math.max(65536,int('PREVIEW_MAX_HTML_BYTES',2097152)),
  previewMaxResourceBytes:Math.max(65536,int('PREVIEW_MAX_RESOURCE_BYTES',8388608)), previewMaxDownloadBytes:Math.max(1048576,int('PREVIEW_MAX_DOWNLOAD_BYTES',33554432)),
  previewUserAgent:process.env.PREVIEW_USER_AGENT||'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0',
  publicRateLimitWindowMs:Math.max(10000,int('PUBLIC_RATE_LIMIT_WINDOW_MS',60000)), publicRateLimitMax:Math.max(5,int('PUBLIC_RATE_LIMIT_MAX',60)), scanRateLimitMax:Math.max(1,int('SCAN_RATE_LIMIT_MAX',12)),
  scanTimeoutMs:Math.max(3000,int('SCAN_TIMEOUT_MS',12000)), scanMaxBytes:Math.max(65536,int('SCAN_MAX_BYTES',1048576)),
  virusTotalApiKey:process.env.VIRUSTOTAL_API_KEY||'', googleWebRiskApiKey:process.env.GOOGLE_WEB_RISK_API_KEY||'', storeScanHistory:bool('STORE_SCAN_HISTORY'),
  openPhishEnabled:bool('OPENPHISH_ENABLED',true), openPhishFeedUrl:process.env.OPENPHISH_FEED_URL||'https://openphish.com/feed.txt',
  threatFeedRefreshMs:Math.max(60*60*1000,int('THREAT_FEED_REFRESH_MS',12*60*60*1000)), threatFeedCachePath:process.env.THREAT_FEED_CACHE_PATH||'/app/data/openphish-cache.json',
  clamavHost:process.env.CLAMAV_HOST||'', clamavPort:int('CLAMAV_PORT',3310),
  browserTicketTtlMs:Math.max(15000,Math.min(300000,int('BROWSER_TICKET_TTL_MS',90000)))
};

const pool = new ProxyPool(config);
await pool.loadState();
await initThreatIntel(config).catch(error => console.error('[threat-intel] init:', error.message));

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', bool('TRUST_PROXY') ? 1 : false);
app.use(helmet({ contentSecurityPolicy:false, crossOriginEmbedderPolicy:false }));
app.use(express.json({ limit:'64kb' }));
app.use((req,res,next)=>{
  const frontendAsset=/\.(?:html|js|css)$/i.test(req.path)||['/','/tester','/preview','/browser','/scanner','/api','/api/docs'].includes(req.path);
  if(frontendAsset){res.set('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');res.set('Pragma','no-cache');res.set('Expires','0');res.set('Surrogate-Control','no-store');}
  next();
});
app.use(express.static(path.join(root,'public'),{maxAge:0,etag:false,lastModified:false}));

const nodeRef=node=>createHash('sha256').update(node.id).digest('hex').slice(0,24);
const findNodeByRef=ref=>[...pool.nodes.values()].find(node=>nodeRef(node)===ref)||null;
const safeNode=node=>({
  ref:nodeRef(node),protocol:node.protocol,country:normalizeCountry(node.country),countryName:countryName(node.country),city:node.city,region:node.region,
  anonymity:node.anonymity,status:node.status,latencyMs:node.latencyMs,lastCheck:node.lastCheck,lastSuccess:node.lastSuccess,
  address:config.exposeAddresses?`${node.ip}:${node.port}`:'hidden',reliability:(node.successes||0)+(node.failures||0)?Math.round((node.successes||0)/((node.successes||0)+(node.failures||0))*100):null
});
const selector=body=>({country:body?.country?normalizeCountry(body.country):undefined,region:body?.region?String(body.region):undefined,protocol:body?.protocol?String(body.protocol).toLowerCase():undefined});

const buckets=new Map();
const rateLimit=max=>(req,res,next)=>{max||=config.publicRateLimitMax;const now=Date.now(),key=`${req.ip||req.socket.remoteAddress||'unknown'}:${req.path}`;let b=buckets.get(key);if(!b||b.resetAt<=now)b={count:0,resetAt:now+config.publicRateLimitWindowMs};b.count++;buckets.set(key,b);res.set('x-ratelimit-limit',String(max));res.set('x-ratelimit-remaining',String(Math.max(0,max-b.count)));if(b.count>max)return res.status(429).json({error:'Public rate limit exceeded. Try again shortly.'});next();};
setInterval(()=>{const now=Date.now();for(const[k,b]of buckets)if(b.resetAt<=now)buckets.delete(k);},60000).unref();
const requireAdmin=(req,res,next)=>!config.adminToken||req.get('x-admin-token')!==config.adminToken?res.status(401).json({error:'Admin token required'}):next();

const statsHandler=(_req,res)=>res.json(pool.stats());
const configHandler=(_req,res)=>res.json({
  exposeNodeAddresses:config.exposeAddresses,matrixMaxNodes:config.matrixMaxNodes,previewSessionTtlMs:config.previewSessionTtlMs,previewTimeoutMs:config.previewTimeoutMs,publicTools:true,previewAllowsAllPublicDomains:true,
  scannerProviders:{localHeuristics:true,openPhish:threatIntelStatus(),clamAV:{configured:Boolean(config.clamavHost)},virusTotal:Boolean(config.virusTotalApiKey),googleWebRisk:Boolean(config.googleWebRiskApiKey)},
  storeScanHistory:config.storeScanHistory,apiVersion:'v1',browserBridge:{supported:true,ticketTtlMs:config.browserTicketTtlMs,extensionDownload:'/downloads/nekoroute-firefox-bridge.zip'},
  disclaimer:'NekoRoute is provided for regional availability, moderation, compatibility and defensive security analysis. Users are responsible for their use of the service and for complying with applicable laws and site terms.',
  privacyNotice:'Target website traffic is fetched through the selected proxy. NekoRoute does not guarantee anonymity or zero trace at the host, proxy, network-provider, or third-party reputation-provider layer.'
});
const filtersFromQuery=req=>({country:req.query.country?normalizeCountry(req.query.country):undefined,region:req.query.region?String(req.query.region):undefined,protocol:req.query.protocol?.toLowerCase(),status:req.query.status?.toLowerCase()});
const proxiesHandler=(req,res)=>{const rows=pool.list(filtersFromQuery(req));const limit=Math.max(1,Math.min(500,Number(req.query.limit||100)));const offset=Math.max(0,Number(req.query.offset||0));res.set({'x-total-count':String(rows.length),'x-offset':String(offset),'x-limit':String(limit)}).json(rows.slice(offset,offset+limit).map(safeNode));};
const nodesV1Handler=(req,res)=>{const rows=pool.list(filtersFromQuery(req));const pageSize=Math.max(1,Math.min(200,Number(req.query.pageSize||req.query.limit||50)));const pages=Math.max(1,Math.ceil(rows.length/pageSize));const page=Math.max(1,Math.min(pages,Number(req.query.page||1)));const offset=(page-1)*pageSize;res.json({items:rows.slice(offset,offset+pageSize).map(safeNode),total:rows.length,page,pageSize,pages,hasPrevious:page>1,hasNext:page<pages});};
const regionsHandler=(_req,res)=>{const by=pool.stats().byRegion||{};res.json(Object.entries(by).sort((a,b)=>b[1]-a[1]).map(([region,count])=>({region,count})));};
const countriesHandler=(req,res)=>{const by=pool.stats().byCountry||{};const wanted=req.query.region?String(req.query.region):null;const rows=Object.entries(by).map(([code,count])=>{const c=normalizeCountry(code);return{code:c,name:countryName(c),region:regionForCountry(c),count};}).filter(x=>!wanted||x.region===wanted).sort((a,b)=>a.name.localeCompare(b.name));res.json(rows);};

app.get(['/api/health','/api/v1/health'],(_req,res)=>res.json({ok:true,service:'NekoRoute',version:'0.5.3',nodes:pool.nodes.size}));
app.get(['/api/stats','/api/v1/stats'],statsHandler);
app.get(['/api/config','/api/v1/config'],configHandler);
app.get(['/api/proxies','/api/v1/proxies'],proxiesHandler);
app.get('/api/v1/nodes',nodesV1Handler);
app.get('/api/v1/regions',regionsHandler);
app.get('/api/v1/countries',countriesHandler);
app.get('/api/v1/threat-intel',(_req,res)=>res.json(threatIntelStatus()));
app.get('/api/v1',(_req,res)=>res.json({
  service:'NekoRoute',version:'0.5.3',docs:'/api/docs',openapi:'/api/openapi.json',endpoints:{
    health:'GET /api/v1/health',stats:'GET /api/v1/stats',regions:'GET /api/v1/regions',countries:'GET /api/v1/countries?region=Europe',nodes:'GET /api/v1/nodes?status=online&country=FR',
    test:'POST /api/v1/test',matrix:'POST /api/v1/test-matrix',scan:'POST /api/v1/scan',previewSession:'POST /api/v1/preview/session',previewResources:'GET /api/v1/preview/session/:id/resources',browserTicket:'POST /api/v1/browser-ticket',threatIntel:'GET /api/v1/threat-intel'
  }
}));
app.get('/api/openapi.json',(_req,res)=>res.json({openapi:'3.1.0',info:{title:'NekoRoute Public API',version:'0.5.3',description:'Regional availability diagnostics, defensive scanning, proxy-pool metadata and safe preview sessions.'},paths:{
  '/api/v1/health':{get:{summary:'Service health'}},'/api/v1/stats':{get:{summary:'Proxy pool statistics'}},'/api/v1/regions':{get:{summary:'Region counts'}},'/api/v1/countries':{get:{summary:'Country names and counts'}},'/api/v1/nodes':{get:{summary:'Filtered public node metadata'}},
  '/api/v1/test':{post:{summary:'Test one URL through a selected/best route'}},'/api/v1/test-matrix':{post:{summary:'Compare one URL across multiple routes'}},'/api/v1/scan':{post:{summary:'Defensive website scan through a proxy'}},'/api/v1/preview/session':{post:{summary:'Create a safe preview session'}},'/api/v1/preview/session/{id}/resources':{get:{summary:'List page-linked resources discovered in an active preview session'}},'/api/v1/browser-ticket':{post:{summary:'Create a one-time ticket for the optional local Firefox Bridge extension'}},'/api/v1/browser-ticket/{ticket}':{get:{summary:'Consume a one-time Firefox Bridge ticket'}}
}}));

app.post('/api/admin/refresh',requireAdmin,async(_req,res,next)=>{try{res.json(await pool.refreshSources());}catch(e){next(e);}});
app.post('/api/admin/sweep',requireAdmin,async(_req,res,next)=>{try{await pool.healthSweep();res.json({ok:true,stats:pool.stats()});}catch(e){next(e);}});
app.post('/api/admin/threat-intel/refresh',requireAdmin,async(_req,res,next)=>{try{res.json(await refreshThreatIntel(config));}catch(e){next(e);}});

const testRouteHandler=async(req,res,next)=>{try{const target=await validatePublicTarget(req.body?.url),sel=selector(req.body);let node=req.body?.nodeRef?findNodeByRef(String(req.body.nodeRef)):pool.select(sel);if(!node||node.status!=='online')return res.status(503).json({error:'No healthy proxy matches that selection'});let lastError;for(let i=0;i<3&&node;i++)try{const r=await requestViaProxy(node,target,{timeoutMs:config.testTimeoutMs,maxBytes:config.maxTestBytes});return res.json({ok:true,node:safeNode(node),target:target.toString(),statusCode:r.statusCode,statusText:http.STATUS_CODES[r.statusCode]||'',latencyMs:r.latencyMs,contentType:r.headers['content-type']||null,location:r.headers.location||null,preview:r.body.slice(0,6000)});}catch(e){lastError=e;node.status='degraded';node.consecutiveFailures=(node.consecutiveFailures||0)+1;node=pool.list({...sel,status:'online'}).find(n=>n.id!==node?.id)||null;}res.status(502).json({error:lastError?.message||'All matching routes failed'});}catch(e){next(e);}};
const testMatrixHandler=async(req,res,next)=>{try{const target=await validatePublicTarget(req.body?.url),sel=selector(req.body),count=Math.max(1,Math.min(config.matrixMaxNodes,Number(req.body?.limit||8)));let nodes=pool.list({...sel,status:'online'});if(req.body?.nodeRef){const n=findNodeByRef(String(req.body.nodeRef));nodes=n&&n.status==='online'?[n]:[];}nodes=nodes.slice(0,count);if(!nodes.length)return res.status(503).json({error:'No healthy proxies match that selection'});const limit=pLimit(config.matrixConcurrency),started=Date.now();const results=await Promise.all(nodes.map(node=>limit(async()=>{try{const r=await requestViaProxy(node,target,{timeoutMs:config.testTimeoutMs,maxBytes:8192,headersOnly:true});return{ok:true,node:safeNode(node),statusCode:r.statusCode,statusText:http.STATUS_CODES[r.statusCode]||'',latencyMs:r.latencyMs,location:r.headers.location||null,contentType:r.headers['content-type']||null};}catch(e){return{ok:false,node:safeNode(node),statusCode:null,statusText:'',latencyMs:null,error:String(e.message||e)};}})));const counts={};for(const r of results){const k=r.statusCode==null?'error':String(r.statusCode);counts[k]=(counts[k]||0)+1;}res.json({ok:true,target:target.toString(),durationMs:Date.now()-started,tested:results.length,counts,results});}catch(e){next(e);}};
const scanHandler=async(req,res,next)=>{try{const target=await validatePublicTarget(req.body?.url),requested=req.body?.nodeRef?findNodeByRef(String(req.body.nodeRef)):null,node=requested||pool.select(selector(req.body));if(!node||node.status!=='online')return res.status(503).json({error:'No healthy proxy matches that selection'});const report=await scanWebsite(node,target.toString(),config),output={ok:true,...report,node:safeNode(node),notice:'Heuristic, local-feed and reputation results are indicators, not a guarantee that a site is safe or malicious.'};if(config.storeScanHistory)saveScanResult({target:report.target,nodeId:node.id,country:node.country,verdict:report.verdict,score:report.score,statusCode:report.statusCode,findings:report.findings,providers:report.providers}).catch(e=>console.error('[scanner] persist:',e.message));res.json(output);}catch(e){next(e);}};
app.post(['/api/test-route','/api/v1/test'],rateLimit(),testRouteHandler);
app.post(['/api/test-matrix','/api/v1/test-matrix'],rateLimit(),testMatrixHandler);
app.post(['/api/scan','/api/v1/scan'],rateLimit(config.scanRateLimitMax),scanHandler);

const sessions=new Map();
setInterval(()=>{const now=Date.now();for(const[id,s]of sessions)if(s.expiresAt<=now)sessions.delete(id);},60000).unref();
const getSession=id=>{const s=sessions.get(id);if(!s||s.expiresAt<=Date.now()){sessions.delete(id);return null;}return s;};
const absolute=(value,base)=>{try{const u=new URL(value,base);return['http:','https:'].includes(u.protocol)?u.toString():null;}catch{return null;}};
const pageUrl=(id,url)=>`/api/preview/${encodeURIComponent(id)}?url=${encodeURIComponent(url)}`;
function registerResource(id,session,url,kind='resource',referer=''){
  const token=createHash('sha256').update(`${kind}\0${url}\0${referer||''}`).digest('hex').slice(0,28);
  if(session.resources.size>2500){const first=session.resources.keys().next().value;if(first)session.resources.delete(first);}
  session.resources.set(token,{url,kind,referer:referer||''});
  return `/api/preview-resource/${encodeURIComponent(id)}/${token}`;
}
function rewriteCss(css,base,id,session){
  let out=String(css).replace(/url\(\s*(['"]?)([^'"\)]+)\1\s*\)/gi,(m,_q,v)=>{const raw=v.trim();if(/^(data:|blob:|#)/i.test(raw))return m;const u=absolute(raw,base);return u?`url("${registerResource(id,session,u,'resource',base)}")`:m;});
  out=out.replace(/@import\s+(?:url\()?\s*(['"])([^'"]+)\1\s*\)?([^;]*);/gi,(m,_q,v,tail)=>{const u=absolute(v,base);return u?`@import url("${registerResource(id,session,u,'style',base)}")${tail||''};`:m;});
  return out;
}
const mediaExt=/\.(?:mp3|m4a|aac|wav|ogg|oga|opus|flac|mp4|m4v|webm|mov|jpg|jpeg|png|gif|webp|avif|svg|pdf)(?:$|[?#])/i;
function rewriteSrcset(value,base,id,session){return String(value||'').split(',').map(part=>{const bits=part.trim().split(/\s+/);const u=absolute(bits[0],base);if(u)bits[0]=registerResource(id,session,u,'resource',base);return bits.join(' ');}).join(', ');}
function compactText(value,max=280){const t=String(value||'').replace(/\s+/g,' ').trim();return t.length>max?t.slice(0,max-1)+'…':t;}
function collectPageHints($,rawHtml,base){
  const links=[]; const media=[]; const seenLinks=new Set(); const seenMedia=new Set();
  const addLink=(url,label='Link')=>{const u=absolute(url,base);if(!u||seenLinks.has(u))return;seenLinks.add(u);links.push({url:u,label:compactText(label||u,120)});};
  const addMedia=(url,label='Media')=>{const u=absolute(url,base);if(!u||seenMedia.has(u))return;seenMedia.add(u);media.push({url:u,label:compactText(label||u,120)});};
  $('a[href]').each((_i,e)=>{const a=$(e),raw=a.attr('href'),label=a.text()||a.attr('title')||a.attr('aria-label')||raw;if(!raw)return;mediaExt.test(raw)||a.is('[download]')?addMedia(raw,label):addLink(raw,label);});
  for(const[sel,attr]of[['audio','src'],['video','src'],['source','src'],['track','src']])$(sel).each((_i,e)=>{const raw=$(e).attr(attr);if(raw)addMedia(raw,$(e).attr('title')||$(e).attr('type')||raw);});
  for(const key of ['og:audio','og:audio:url','og:video','og:video:url','twitter:player:stream']){
    const raw=$(`meta[property="${key}"],meta[name="${key}"]`).first().attr('content'); if(raw)addMedia(raw,key);
  }
  $('*').each((_i,e)=>{for(const [name,val] of Object.entries(e.attribs||{})){if(!val)continue;const n=String(name).toLowerCase();if(/(?:src|href|url|download|media|audio|file)/.test(n)&&mediaExt.test(String(val)))addMedia(val,n);}});
  const normalized=String(rawHtml||'').replace(/\\\//g,'/').replace(/&amp;/g,'&');
  for(const m of normalized.matchAll(/https?:\/\/[^\s"'<>\\]+/gi)){
    const raw=m[0].replace(/[),.;]+$/,''); if(mediaExt.test(raw))addMedia(raw,'Detected media URL');
  }
  for(const m of normalized.matchAll(/["']([^"']+\.(?:mp3|m4a|aac|wav|ogg|oga|opus|flac|mp4|m4v|webm|mov|pdf)(?:\?[^"']*)?)["']/gi))addMedia(m[1],'Detected media URL');
  const title=compactText($('title').first().text()||$('meta[property="og:title"]').attr('content')||new URL(base).hostname,160);
  const description=compactText($('meta[name="description"]').attr('content')||$('meta[property="og:description"]').attr('content')||'',500);
  const bodyClone=$('body').clone();bodyClone.find('script,style,template').remove();const bodyText=compactText(bodyClone.text(),2400);
  return {title,description,bodyText,links:links.slice(0,80),media:media.slice(0,80)};
}
function resourcePanel(hints,id,session,base,full=false){
  const media=hints.media.map(item=>{const href=registerResource(id,session,item.url,'download',base)+'?download=1';return `<li style="margin:7px 0;overflow-wrap:anywhere"><a href="${href}" style="color:#34d399;text-decoration:underline" download>${escapeHtml(item.label||'Download media')}</a><div style="font:11px ui-monospace,monospace;color:#71717a">${escapeHtml(item.url)}</div></li>`;}).join('');
  const links=hints.links.map(item=>`<li style="margin:7px 0;overflow-wrap:anywhere"><a href="#" data-neko-url="${escapeHtml(item.url)}" style="color:#67e8f9;text-decoration:underline">${escapeHtml(item.label||item.url)}</a><div style="font:11px ui-monospace,monospace;color:#71717a">${escapeHtml(item.url)}</div></li>`).join('');
  if(!media&&!links&&!full)return '';
  const intro=full?`<h2 style="all:initial;display:block!important;color:#e4e4e7!important;font:700 20px system-ui!important;margin:0 0 8px!important">${escapeHtml(hints.title||'Proxied page')}</h2>${hints.description?`<p style="all:initial;display:block!important;color:#a1a1aa!important;font:14px/1.5 system-ui!important;margin:0 0 10px!important">${escapeHtml(hints.description)}</p>`:''}${hints.bodyText?`<p style="all:initial;display:block!important;white-space:pre-wrap!important;color:#d4d4d8!important;font:14px/1.5 system-ui!important;margin:0 0 14px!important">${escapeHtml(hints.bodyText)}</p>`:''}`:'';
  const body=`${intro}${media?`<div style="all:initial;display:block!important;margin-top:12px!important"><b style="color:#fbbf24;font:700 14px system-ui">Detected media/downloads (${hints.media.length})</b><ul style="all:initial;display:block!important;padding-left:20px!important;margin:6px 0!important;color:#e4e4e7!important;font:13px/1.4 system-ui!important">${media}</ul></div>`:''}${links?`<div style="all:initial;display:block!important;margin-top:12px!important"><b style="color:#a7f3d0;font:700 14px system-ui">Page links (${hints.links.length})</b><ul style="all:initial;display:block!important;padding-left:20px!important;margin:6px 0!important;color:#e4e4e7!important;font:13px/1.4 system-ui!important">${links}</ul></div>`:''}`;
  if(full)return `<section data-neko-fallback style="all:initial;display:block!important;box-sizing:border-box!important;max-width:1100px!important;margin:24px auto!important;padding:20px!important;background:#090d0b!important;color:#e4e4e7!important;border:1px solid #14532d!important;border-radius:16px!important;font-family:system-ui!important">${body||'<p style="color:#a1a1aa">The remote page contains no server-rendered content after scripts were disabled.</p>'}</section>`;
  return `<details data-neko-resources style="all:initial;display:block!important;box-sizing:border-box!important;margin:16px!important;padding:12px 14px!important;background:#090d0b!important;color:#e4e4e7!important;border:1px solid #14532d!important;border-radius:12px!important;font-family:system-ui!important"><summary style="cursor:pointer;color:#a7f3d0;font:700 13px system-ui">NekoRoute detected resources${hints.media.length?` · ${hints.media.length} media/download`:''}</summary>${body}</details>`;
}
function rewriteHtml(html,base,id,session){
  const $=cheerio.load(html,{decodeEntities:false});
  const hints=collectPageHints($,html,base);
  $('script,iframe,frame,object,embed,portal').remove();$('base').remove();
  $('meta[http-equiv]').each((_i,e)=>{const v=String($(e).attr('http-equiv')||'').toLowerCase();if(v==='content-security-policy'||v==='refresh')$(e).remove();});
  $('*').each((_i,e)=>{for(const n of Object.keys(e.attribs||{}))if(/^on/i.test(n))$(e).removeAttr(n);});
  $('a[href]').each((_i,e)=>{const a=$(e),raw=a.attr('href');if(!raw||raw.startsWith('#'))return;const u=absolute(raw,base);if(!u){a.attr('href','#').attr('data-neko-blocked','true');return;}const explicit=a.is('[download]')||mediaExt.test(u);if(explicit){a.attr('href',registerResource(id,session,u,'download',base)+'?download=1').attr('rel','nofollow noopener');}else{a.attr('href','#').attr('data-neko-url',u);}});
  for(const[sel,attr,kind]of[['img','src','resource'],['source','src','media'],['video','src','media'],['video','poster','resource'],['audio','src','media'],['track','src','media'],['link[rel="stylesheet"]','href','style'],['link[rel="icon"]','href','resource']])$(sel).each((_i,e)=>{const u=absolute($(e).attr(attr),base);if(u)$(e).attr(attr,registerResource(id,session,u,kind,base)).removeAttr('integrity').removeAttr('crossorigin');});
  $('img[srcset],source[srcset]').each((_i,e)=>$(e).attr('srcset',rewriteSrcset($(e).attr('srcset'),base,id,session)));
  $('[style]').each((_i,e)=>$(e).attr('style',rewriteCss($(e).attr('style'),base,id,session)));$('style').each((_i,e)=>$(e).text(rewriteCss($(e).html()||'',base,id,session)));
  $('form').each((_i,e)=>{const form=$(e);const method=String(form.attr('method')||'get').toLowerCase();const action=absolute(form.attr('action')||base,base);if(method==='get'&&action&&!form.find('input[type="password"],input[type="file"]').length){form.attr('data-neko-get-form','true').attr('data-neko-action',action).attr('action','#').attr('method','get');}else{form.attr('data-neko-form-disabled','true');form.find('input,textarea,select,button').attr('disabled','disabled');}});
  const meaningfulClone=$('body').clone();meaningfulClone.find('style,template').remove();const meaningfulText=String(meaningfulClone.text()||'').replace(/\s+/g,' ').trim();
  const meaningfulNodes=$('body a[data-neko-url],body a[href^="/api/preview-resource"],body img[src],body audio[src],body video[src],body form[data-neko-get-form]').length;
  const needsFallback=meaningfulText.length<80&&meaningfulNodes<3;
  $('body').prepend(`<div style="position:sticky;top:0;z-index:2147483647;padding:8px 12px;background:#07110b;color:#a7f3d0;border-bottom:1px solid #14532d;font:12px system-ui">NekoRoute proxied preview · safe static rendering · page-linked downloads enabled${needsFallback?' · client-rendered page fallback active':''}</div>`);
  if(needsFallback)$('body').append(resourcePanel(hints,id,session,base,true));
  else if(hints.media.length)$('body').append(resourcePanel(hints,id,session,base,false));
  $('body').append(`<script>(function(){document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a[data-neko-url]');if(!a)return;e.preventDefault();parent.postMessage({type:'nekoroute-preview-nav',url:a.getAttribute('data-neko-url')},'*')},true);document.addEventListener('submit',function(e){var f=e.target;if(!f||!f.matches||!f.matches('form[data-neko-get-form]')){e.preventDefault();return;}e.preventDefault();var action=f.getAttribute('data-neko-action');try{var u=new URL(action);var fd=new FormData(f);for(var pair of fd.entries())u.searchParams.append(pair[0],pair[1]);parent.postMessage({type:'nekoroute-preview-nav',url:u.toString()},'*')}catch(_){}},true)})()</script>`);
  return $.html();
}
const escapeHtml=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const errorHtml=m=>`<!doctype html><html><body style="background:#050807;color:#e4e4e7;font:15px system-ui"><div style="max-width:760px;margin:64px auto;padding:24px;border:1px solid #27272a;border-radius:20px"><h1 style="color:#34d399">Preview blocked</h1><p>${escapeHtml(m||'Preview failed')}</p></div></body></html>`;
function nonHtmlPreview(id,session,url,type){const src=registerResource(id,session,url,'download');const isAudio=type.startsWith('audio/'),isVideo=type.startsWith('video/'),isImage=type.startsWith('image/'),isPdf=type.includes('pdf');const player=isAudio?`<audio controls style="width:100%" src="${src}"></audio>`:isVideo?`<video controls style="max-width:100%;max-height:70vh" src="${src}"></video>`:isImage?`<img style="max-width:100%;max-height:75vh" src="${src}"/>`:isPdf?`<iframe style="width:100%;height:70vh;border:0" src="${src}"></iframe>`:'';return`<!doctype html><html><body style="background:#050807;color:#e4e4e7;font:15px system-ui"><div style="max-width:1000px;margin:30px auto;padding:24px"><h2 style="color:#34d399">Proxied resource</h2><p>${escapeHtml(type)}</p>${player}<p><a style="color:#34d399" href="${src}?download=1">Download this page-linked resource through the selected proxy</a></p></div></body></html>`;}


const browserTickets=new Map();
setInterval(()=>{const now=Date.now();for(const[k,t]of browserTickets)if(t.expiresAt<=now)browserTickets.delete(k);},30000).unref();
const browserTicketHandler=async(req,res,next)=>{try{const target=await validatePublicTarget(req.body?.url),requested=req.body?.nodeRef?findNodeByRef(String(req.body.nodeRef)):null,node=requested||pool.select(selector(req.body));if(!node||node.status!=='online')return res.status(503).json({error:'No healthy proxy matches that selection'});const ticket=randomUUID(),expiresAt=Date.now()+config.browserTicketTtlMs;browserTickets.set(ticket,{nodeId:node.id,target:target.toString(),expiresAt});res.json({ok:true,ticket,ticketUrl:`/api/v1/browser-ticket/${encodeURIComponent(ticket)}`,expiresAt:new Date(expiresAt).toISOString(),target:target.toString(),node:safeNode(node),note:'Consume this ticket with the NekoRoute Firefox Bridge extension. Tickets are single-use and expire quickly.'});}catch(e){next(e);}};
app.post('/api/v1/browser-ticket',rateLimit(),browserTicketHandler);
app.get('/api/v1/browser-ticket/:ticket',rateLimit(),(req,res)=>{const key=String(req.params.ticket),ticket=browserTickets.get(key);if(!ticket||ticket.expiresAt<=Date.now()){browserTickets.delete(key);return res.status(410).json({error:'Browser ticket expired or already used'});}const node=pool.nodes.get(ticket.nodeId);if(!node||node.status!=='online'){browserTickets.delete(key);return res.status(503).json({error:'Selected proxy is no longer online'});}browserTickets.delete(key);const type=node.protocol==='socks5'?'socks':node.protocol;res.set('cache-control','no-store').json({ok:true,target:ticket.target,proxy:{type,host:node.ip,port:node.port,proxyDNS:type==='socks'||type==='socks4',failoverTimeout:8},node:safeNode(node)});});

const previewSessionHandler=async(req,res,next)=>{try{const target=await validatePublicTarget(req.body?.url),requested=req.body?.nodeRef?findNodeByRef(String(req.body.nodeRef)):null,node=requested||pool.select(selector(req.body));if(!node||node.status!=='online')return res.status(503).json({error:'No healthy proxy matches that selection'});const id=randomUUID(),expiresAt=Date.now()+config.previewSessionTtlMs;sessions.set(id,{nodeId:node.id,expiresAt,resources:new Map()});res.json({ok:true,sessionId:id,expiresAt:new Date(expiresAt).toISOString(),url:target.toString(),frameUrl:pageUrl(id,target.toString()),node:safeNode(node),capabilities:{navigation:true,getForms:true,pageLinkedMedia:true,pageLinkedDownloads:true,remoteScripts:false,cookies:false,postForms:false}});}catch(e){next(e);}};
app.post(['/api/preview-session','/api/v1/preview/session'],rateLimit(),previewSessionHandler);
app.get('/api/v1/preview/session/:id/resources',rateLimit(),(req,res)=>{const s=getSession(String(req.params.id));if(!s)return res.status(410).json({error:'Preview session expired'});const rows=[...s.resources.entries()].map(([token,entry])=>({token,kind:entry.kind,url:entry.url,fetchUrl:`/api/preview-resource/${encodeURIComponent(req.params.id)}/${token}`,downloadUrl:`/api/preview-resource/${encodeURIComponent(req.params.id)}/${token}?download=1`}));res.json({sessionId:req.params.id,expiresAt:new Date(s.expiresAt).toISOString(),count:rows.length,resources:rows});});
app.get('/api/preview/:id',async(req,res)=>{const s=getSession(String(req.params.id));if(!s)return res.status(410).type('html').send(errorHtml('Preview session expired.'));const node=pool.nodes.get(s.nodeId);if(!node||node.status==='offline')return res.status(503).type('html').send(errorHtml('Selected proxy is unavailable.'));try{const target=await validatePublicTarget(String(req.query.url||'')),r=await requestViaProxy(node,target,{timeoutMs:config.previewTimeoutMs,maxBytes:config.previewMaxHtmlBytes,headers:{accept:'text/html,application/xhtml+xml,audio/*,video/*,image/*,application/pdf;q=0.8,text/plain;q=0.7,*/*;q=0.2','user-agent':config.previewUserAgent,'accept-language':'en-GB,en;q=0.9'}});if(r.statusCode>=300&&r.statusCode<400&&r.headers.location){const next=absolute(r.headers.location,target);if(next){await validatePublicTarget(next);return res.redirect(302,pageUrl(req.params.id,next));}}const type=String(r.headers['content-type']||'text/html').toLowerCase();if(!type.includes('html')){const allowed=type.startsWith('audio/')||type.startsWith('video/')||type.startsWith('image/')||type.includes('application/pdf');if(allowed)return res.status(200).type('html').send(nonHtmlPreview(req.params.id,s,target.toString(),type));return res.status(415).type('html').send(errorHtml(`Preview cannot render ${type}.`));}res.status(r.statusCode||200).set({'cache-control':'no-store','content-type':'text/html; charset=utf-8'}).send(rewriteHtml(r.body,target.toString(),req.params.id,s));}catch(e){res.status(400).type('html').send(errorHtml(e.message||e));}});
app.get('/api/preview-resource/:id/:token',async(req,res)=>{const s=getSession(String(req.params.id));if(!s)return res.status(410).end();const entry=s.resources.get(String(req.params.token));if(!entry)return res.status(404).end();const node=pool.nodes.get(s.nodeId);if(!node||node.status==='offline')return res.status(503).end();try{const target=await validatePublicTarget(entry.url);const range=req.get('range');const r=await requestViaProxy(node,target,{timeoutMs:config.previewTimeoutMs,maxBytes:req.query.download==='1'?config.previewMaxDownloadBytes:config.previewMaxResourceBytes,headers:{accept:'*/*','user-agent':config.previewUserAgent,...(entry.referer?{referer:entry.referer}:{}),...(range?{range}:{})}});if(r.statusCode>=300&&r.statusCode<400&&r.headers.location){const next=absolute(r.headers.location,target);if(next){await validatePublicTarget(next);const newUrl=registerResource(req.params.id,s,next,entry.kind,entry.referer);return res.redirect(302,newUrl+(req.query.download==='1'?'?download=1':''));}}const type=String(r.headers['content-type']||'application/octet-stream').toLowerCase();const normalAllowed=type.startsWith('image/')||type.startsWith('font/')||type.startsWith('audio/')||type.startsWith('video/')||type.includes('text/css')||type.includes('font-woff')||type.includes('application/pdf');const downloadAllowed=entry.kind==='download'&&(normalAllowed||type.includes('application/octet-stream')||type.includes('application/force-download')||type.includes('application/download')||type.includes('application/x-download')||type.includes('binary/octet-stream'));if(!normalAllowed&&!downloadAllowed)return res.status(415).end();const headers={'cache-control':'private, max-age=120','content-type':r.headers['content-type']||'application/octet-stream'};if(r.headers['content-range'])headers['content-range']=r.headers['content-range'];if(r.headers['accept-ranges'])headers['accept-ranges']=r.headers['accept-ranges'];if(req.query.download==='1'){const remoteDisposition=String(r.headers['content-disposition']||'');const match=/filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(remoteDisposition);let filename=path.basename(target.pathname)||'download';if(match?.[1]){try{filename=decodeURIComponent(match[1].trim());}catch{filename=match[1].trim();}}headers['content-disposition']=`attachment; filename="${filename.replace(/["\\\r\n]/g,'_')}"`;}if(type.includes('text/css')){const body=rewriteCss(r.body,target.toString(),req.params.id,s);headers['content-length']=String(Buffer.byteLength(body));return res.status(r.statusCode||200).set(headers).send(body);}headers['content-length']=String(r.bodyBuffer.length);return res.status(r.statusCode||200).set(headers).send(r.bodyBuffer);}catch{return res.status(404).end();}});

app.use((err,_req,res,_next)=>{console.error(err);res.status(400).json({error:err.message||'Request failed'});});
app.get('/tester',(_req,res)=>res.sendFile(path.join(root,'public','tester.html')));app.get('/preview',(_req,res)=>res.sendFile(path.join(root,'public','preview.html')));app.get('/browser',(_req,res)=>res.sendFile(path.join(root,'public','browser.html')));app.get('/scanner',(_req,res)=>res.sendFile(path.join(root,'public','scanner.html')));app.get(['/api','/api/docs'],(_req,res)=>res.sendFile(path.join(root,'public','api-docs.html')));app.get('/{*splat}',(_req,res)=>res.sendFile(path.join(root,'public','index.html')));
const server=app.listen(config.port,'0.0.0.0',()=>console.log(`[NekoRoute] listening on :${config.port}`));
let sourceBusy=false,sweepBusy=false;
const refresh=async()=>{if(sourceBusy)return;sourceBusy=true;try{const r=await pool.refreshSources();console.log(`[sources] ${r.retained?'retained':'loaded'} ${r.count} proxies (${r.discoveredThisRefresh??0} seen this refresh)`);for(const stat of r.sourceStats||[]){if(stat.ok)console.log(`[sources:${stat.source}] ${stat.count} proxies${stat.endpoint?` via ${stat.endpoint}`:''}`);else console.error(`[sources:${stat.source}] failed - ${(stat.errors||[]).map(x=>`${x.endpoint}: ${x.error}`).join(' | ')}`);}}catch(e){console.error('[sources]',e.message);}finally{sourceBusy=false;}};
const sweep=async()=>{if(sweepBusy)return;sweepBusy=true;try{await pool.healthSweep();console.log('[health] sweep complete');}catch(e){console.error('[health]',e.message);}finally{sweepBusy=false;}};
refresh().then(sweep);setInterval(refresh,config.sourceRefreshMs).unref();setInterval(sweep,config.healthIntervalMs).unref();setInterval(()=>pool.saveState(),120000).unref();
if(config.openPhishEnabled)setInterval(()=>refreshThreatIntel(config).then(s=>console.log(`[threat-intel] OpenPhish cache ${s.cachedUrls} URLs`)).catch(e=>console.error('[threat-intel]',e.message)),config.threatFeedRefreshMs).unref();
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,async()=>{await pool.saveState();server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),5000).unref();});
