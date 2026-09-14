const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const base = location.origin;
$('#baseUrl').textContent = `${base}/api/v1`;

const endpoints = [
  { method:'GET', path:'/api/v1/health', title:'Service health', desc:'Basic service status, version and current number of remembered proxy nodes.', example:`curl -sS '${base}/api/v1/health'` },
  { method:'GET', path:'/api/v1/stats', title:'Proxy pool statistics', desc:'Online/degraded/offline counts plus country, protocol and region totals and health-cursor state.', example:`curl -sS '${base}/api/v1/stats'` },
  { method:'GET', path:'/api/v1/regions', title:'Regions', desc:'Returns every world region currently represented in the persistent proxy database with counts.', example:`curl -sS '${base}/api/v1/regions'` },
  { method:'GET', path:'/api/v1/countries?region=Europe', title:'Countries', desc:'Returns full country names, ISO-2 codes, regions and node counts. The region query parameter is optional.', params:['region — optional region name'], example:`curl -sS '${base}/api/v1/countries?region=Europe'` },
  { method:'GET', path:'/api/v1/nodes?status=online&country=RU&page=1&pageSize=50', title:'Paginated proxy nodes', desc:'Returns filtered node metadata with items, total, page, pageSize, pages, hasPrevious and hasNext. Raw addresses stay hidden unless EXPOSE_NODE_ADDRESSES is enabled.', params:['status — online | degraded | offline | unknown','country — ISO-2 code such as RU, GB, FR','region — e.g. Europe, Asia','protocol — http | https | socks4 | socks5','page — 1-based page number','pageSize — 1 to 200'], example:`curl -sS '${base}/api/v1/nodes?status=online&country=RU&page=1&pageSize=50'` },
  { method:'POST', path:'/api/v1/test', title:'Single-route URL test', desc:'Tests one public URL through a selected node or the best currently healthy node matching the filters.', body:{url:'https://example.com/',country:'RU',protocol:'socks5'}, example:`curl -sS '${base}/api/v1/test' \\\n  -H 'content-type: application/json' \\\n  -d '{"url":"https://example.com/","country":"RU","protocol":"socks5"}'` },
  { method:'POST', path:'/api/v1/test-matrix', title:'Multi-route status matrix', desc:'Compares one URL across several matching exits and reports HTTP status, latency, content type and redirects for each node.', body:{url:'https://example.com/',country:'RU',limit:8}, example:`curl -sS '${base}/api/v1/test-matrix' \\\n  -H 'content-type: application/json' \\\n  -d '{"url":"https://example.com/","country":"RU","limit":8}'` },
  { method:'POST', path:'/api/v1/scan', title:'Defensive website scan', desc:'Fetches a public website through a matching proxy and runs local heuristics plus configured local/reputation providers.', body:{url:'https://example.com/',country:'DE'}, example:`curl -sS '${base}/api/v1/scan' \\\n  -H 'content-type: application/json' \\\n  -d '{"url":"https://example.com/","country":"DE"}'` },
  { method:'POST', path:'/api/v1/preview/session', title:'Create safe preview session', desc:'Creates an expiring preview session pinned to a selected/best route. The response includes sessionId, frameUrl, node metadata and capabilities.', body:{url:'https://example.com/',country:'RU'}, example:`curl -sS '${base}/api/v1/preview/session' \\\n  -H 'content-type: application/json' \\\n  -d '{"url":"https://example.com/","country":"RU"}'` },
  { method:'POST', path:'/api/v1/browser-ticket', title:'Create Firefox Bridge ticket', desc:'Creates a short-lived one-time route ticket for the optional local Firefox Bridge extension. The extension consumes it and opens the target in a real local Firefox tab using the selected public proxy.', body:{url:'https://example.com/',country:'RU'}, example:`curl -sS '${base}/api/v1/browser-ticket' \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com/","country":"RU"}'` },
  { method:'GET', path:'/api/v1/threat-intel', title:'Threat-intelligence status', desc:'Reports the state of locally cached no-key threat feeds and configured scanner providers.', example:`curl -sS '${base}/api/v1/threat-intel'` },
  { method:'GET', path:'/api/v1/config', title:'Public capabilities/config', desc:'Returns public feature flags and safe operational limits without exposing secrets.', example:`curl -sS '${base}/api/v1/config'` }
];

function methodClass(method){return method==='GET'?'border-emerald-500/25 bg-emerald-500/10 text-emerald-300':'border-sky-500/25 bg-sky-500/10 text-sky-300';}

$('#endpointList').innerHTML = endpoints.map((e,i)=>`
  <article class="glass overflow-hidden rounded-2xl border border-zinc-800">
    <div class="flex flex-col gap-3 border-b border-zinc-800 px-5 py-4 lg:flex-row lg:items-center">
      <span class="w-fit rounded-lg border px-2.5 py-1 font-mono text-xs font-black ${methodClass(e.method)}">${e.method}</span>
      <code class="break-all text-sm text-zinc-200">${esc(e.path)}</code>
      <div class="lg:ml-auto font-bold">${esc(e.title)}</div>
    </div>
    <div class="grid gap-5 p-5 lg:grid-cols-[1fr_1.1fr]">
      <div>
        <p class="text-sm leading-6 text-zinc-400">${esc(e.desc)}</p>
        ${e.params ? `<div class="mt-4"><div class="text-xs font-bold uppercase tracking-wider text-zinc-500">Query parameters</div><div class="mt-2 grid gap-1">${e.params.map(x=>`<code class="text-xs text-zinc-300">${esc(x)}</code>`).join('')}</div></div>` : ''}
        ${e.body ? `<div class="mt-4"><div class="text-xs font-bold uppercase tracking-wider text-zinc-500">Example JSON body</div><pre class="mt-2 overflow-x-auto rounded-xl border border-zinc-800 bg-black/30 p-3 text-xs text-zinc-300">${esc(JSON.stringify(e.body,null,2))}</pre></div>` : ''}
      </div>
      <div>
        <div class="mb-2 flex items-center justify-between"><div class="text-xs font-bold uppercase tracking-wider text-zinc-500">cURL</div><button data-copy="${i}" class="rounded-lg border border-zinc-800 px-2.5 py-1 text-xs text-zinc-400 hover:border-emerald-500/40 hover:text-emerald-300">Copy</button></div>
        <pre class="overflow-x-auto rounded-xl border border-zinc-800 bg-black/40 p-4 text-xs leading-5 text-emerald-200"><code>${esc(e.example)}</code></pre>
      </div>
    </div>
  </article>`).join('');

document.addEventListener('click', async event => {
  const button = event.target.closest('[data-copy]');
  if (!button) return;
  const endpoint = endpoints[Number(button.dataset.copy)];
  if (!endpoint) return;
  await navigator.clipboard.writeText(endpoint.example);
  const before = button.textContent;
  button.textContent = 'Copied';
  setTimeout(()=>button.textContent=before,1000);
});
