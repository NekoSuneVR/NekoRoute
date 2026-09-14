import { esc, flag, countryName, countryLabel, regions, createNodePager } from '/common.js?v=0503-20260914T1520';

const $ = s => document.querySelector(s);
const value = (s, fallback = '') => $(s)?.value ?? fallback;
const setText = (s, text) => { const el = $(s); if (el) el.textContent = text; };
const setHtml = (s, html) => { const el = $(s); if (el) el.innerHTML = html; };
let stats = null;
let lastResult = null;

function statusClass(code) {
  if (code >= 200 && code < 300) return 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300';
  if (code >= 300 && code < 400) return 'border-sky-500/25 bg-sky-500/10 text-sky-300';
  if (code >= 400 && code < 500) return 'border-amber-500/25 bg-amber-500/10 text-amber-300';
  if (code >= 500) return 'border-rose-500/25 bg-rose-500/10 text-rose-300';
  return 'border-zinc-700 bg-zinc-800 text-zinc-300';
}

function fillFilters() {
  setHtml('#regionSelect', '<option value="">All regions</option>' + regions.map(r => `<option>${esc(r)}</option>`).join(''));
  const countries = Object.entries(stats?.byCountry || {}).sort((a,b) => countryName(a[0]).localeCompare(countryName(b[0])));
  setHtml('#countrySelect', '<option value="">All countries</option>' + countries.map(([c,n]) => `<option value="${esc(c)}">${esc(countryLabel(c))} · ${n}</option>`).join(''));
}

const nodePager=createNodePager({
  select:$('#nodeSelect'),previous:$('#nodePrev'),next:$('#nodeNext'),label:$('#nodePage'),pageSize:50,autoLabel:'Auto / multiple',
  getFilters:()=>({region:value('#regionSelect'),country:value('#countrySelect'),protocol:value('#protocolSelect')})
});
const loadNodes=(reset=true)=>nodePager.load({reset});

function renderSummary(results) {
  const count = test => results.filter(test).length;
  setText('#sumTested', results.length); setText('#sum2xx', count(r => r.statusCode >= 200 && r.statusCode < 300));
  setText('#sum3xx', count(r => r.statusCode >= 300 && r.statusCode < 400)); setText('#sum4xx', count(r => r.statusCode >= 400 && r.statusCode < 500));
  setText('#sum5xx', count(r => r.statusCode >= 500)); setText('#sumErrors', count(r => !r.ok || r.statusCode == null));
}

function renderRows(results) {
  setHtml('#resultRows', results.map(r => {
    const n = r.node || {}; const code = r.statusCode == null ? 'ERR' : r.statusCode;
    return `<tr class="hover:bg-emerald-500/[.025]"><td class="px-5 py-3"><span class="inline-flex rounded-lg border px-2.5 py-1 font-mono text-xs font-black ${statusClass(r.statusCode)}">${esc(code)}</span><div class="mt-1 text-xs text-zinc-600">${esc(r.statusText || '')}</div></td><td class="px-4 py-3">${flag(n.country)} <span class="font-semibold">${esc(countryName(n.country))}</span> <span class="text-xs text-zinc-600">(${esc(n.country)})</span><div class="text-xs text-zinc-600">${esc(n.region)} · ${esc(n.city)}</div></td><td class="px-4 py-3 font-mono text-xs text-zinc-300">${esc(n.address)}</td><td class="px-4 py-3"><span class="rounded-lg border border-zinc-800 bg-black/20 px-2 py-1 font-mono text-xs">${esc(n.protocol)}</span></td><td class="px-4 py-3">${r.latencyMs == null ? '—' : `${r.latencyMs} ms`}</td><td class="max-w-[250px] truncate px-4 py-3 text-xs text-zinc-500" title="${esc(r.location || '')}">${esc(r.location || '—')}</td><td class="px-5 py-3 text-xs ${r.ok ? 'text-zinc-400' : 'text-rose-300'}">${esc(r.error || (r.contentType || 'Response received'))}</td></tr>`;
  }).join('') || '<tr><td colspan="7" class="px-5 py-12 text-center text-zinc-500">No results.</td></tr>');
}

async function init() {
  const [statsRes, configRes] = await Promise.all([fetch('/api/stats'), fetch('/api/config')]);
  stats = await statsRes.json(); const config = await configRes.json(); fillFilters();
  setText('#allowlistInfo', `Public availability tester · HTTP/HTTPS ports 80/443 only · private/reserved networks blocked · maximum ${config.matrixMaxNodes || 12} proxies per run · rate limits apply`);
  await loadNodes(true);
}

for (const id of ['regionSelect','countrySelect','protocolSelect']) $('#'+id)?.addEventListener('change', ()=>loadNodes(true));
$('#runBtn')?.addEventListener('click', async () => {
  const body = { url:value('#testUrl'), region:value('#regionSelect')||undefined, country:value('#countrySelect')||undefined, protocol:value('#protocolSelect')||undefined, nodeRef:value('#nodeSelect')||undefined, limit:Number(value('#limitSelect','8')||8) };
  const runBtn=$('#runBtn'); if(runBtn){runBtn.disabled=true;runBtn.textContent='Testing…';} setText('#resultMeta','Running requests through selected exits…');
  try { const res=await fetch('/api/test-matrix',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}); const data=await res.json(); if(!res.ok)throw new Error(data.error||`HTTP ${res.status}`); lastResult=data; renderSummary(data.results||[]);renderRows(data.results||[]);setText('#resultMeta',`${data.tested} proxies · ${data.durationMs} ms total · ${data.target}`); }
  catch(error){setText('#resultMeta',error.message);setHtml('#resultRows',`<tr><td colspan="7" class="px-5 py-12 text-center text-rose-300">${esc(error.message)}</td></tr>`);} finally{if(runBtn){runBtn.disabled=false;runBtn.textContent='Run test';}}
});
$('#copyBtn')?.addEventListener('click',async()=>{if(!lastResult)return;await navigator.clipboard.writeText(JSON.stringify(lastResult,null,2));setText('#copyBtn','Copied');setTimeout(()=>setText('#copyBtn','Copy JSON'),1200);});
init().catch(error=>{setText('#allowlistInfo',error.message);console.error('[tester] init failed:',error);});
