const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const flag = code => code && code.length === 2 ? [...code].map(c => String.fromCodePoint(127397 + c.charCodeAt())).join('') : '🌐';
const regions = ['North America','South America','Europe','Africa','Asia','Oceania','Other'];
let stats = null;

function fillFilters() {
  $('#regionSelect').innerHTML = '<option value="">All regions</option>' + regions.map(r => `<option>${r}</option>`).join('');
  const countries = Object.entries(stats?.byCountry || {}).sort((a,b) => a[0].localeCompare(b[0]));
  $('#countrySelect').innerHTML = '<option value="">All countries</option>' + countries.map(([c,n]) => `<option value="${esc(c)}">${flag(c)} ${esc(c)} · ${n}</option>`).join('');
}

async function loadNodes() {
  const q = new URLSearchParams({ status:'online', limit:'250' });
  if ($('#regionSelect').value) q.set('region', $('#regionSelect').value);
  if ($('#countrySelect').value) q.set('country', $('#countrySelect').value);
  if ($('#protocolSelect').value) q.set('protocol', $('#protocolSelect').value);
  const nodes = await (await fetch('/api/proxies?' + q)).json();
  $('#nodeSelect').innerHTML = '<option value="">Best healthy node automatically</option>' + nodes.map(n => `<option value="${esc(n.ref)}">${flag(n.country)} ${esc(n.country)} · ${esc(n.protocol)} · ${esc(n.address)} · ${n.latencyMs ?? '—'}ms</option>`).join('');
}

function severityClass(severity) {
  if (severity === 'critical') return 'border-rose-500/30 bg-rose-500/10 text-rose-200';
  if (severity === 'high') return 'border-orange-500/30 bg-orange-500/10 text-orange-200';
  if (severity === 'medium') return 'border-amber-500/30 bg-amber-500/10 text-amber-200';
  if (severity === 'low') return 'border-sky-500/30 bg-sky-500/10 text-sky-200';
  return 'border-zinc-700 bg-black/20 text-zinc-300';
}
function verdictClass(verdict) {
  return verdict === 'critical' ? 'text-rose-300' : verdict === 'high' ? 'text-orange-300' : verdict === 'medium' ? 'text-amber-300' : 'text-emerald-300';
}

async function init() {
  const [statsRes, configRes] = await Promise.all([fetch('/api/stats'), fetch('/api/config')]);
  stats = await statsRes.json();
  const config = await configRes.json();
  fillFilters();
  await loadNodes();
  const providers = config.scannerProviders || {};
  $('#providerInfo').textContent = `Local heuristics always enabled · VirusTotal ${providers.virusTotal ? 'enabled' : 'not configured'} · Google Web Risk ${providers.googleWebRisk ? 'enabled' : 'not configured'}`;
}
for (const id of ['regionSelect','countrySelect','protocolSelect']) $('#'+id).addEventListener('change', loadNodes);

$('#scanBtn').addEventListener('click', async () => {
  const body = { url: $('#scanUrl').value, region: $('#regionSelect').value || undefined, country: $('#countrySelect').value || undefined, protocol: $('#protocolSelect').value || undefined, nodeRef: $('#nodeSelect').value || undefined };
  $('#scanBtn').disabled = true; $('#scanBtn').textContent = 'Scanning…'; $('#scanMeta').textContent = 'Fetching without executing remote JavaScript…';
  try {
    const res = await fetch('/api/scan', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body) });
    const data = await res.json(); if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    $('#verdict').className = `mt-1 text-2xl font-black ${verdictClass(data.verdict)}`; $('#verdict').textContent = String(data.verdict || 'unknown').toUpperCase();
    $('#score').textContent = `${data.score}/100`; $('#status').textContent = data.statusCode ?? 'ERR'; $('#latency').textContent = data.latencyMs == null ? '—' : `${data.latencyMs} ms`; $('#findingCount').textContent = (data.findings || []).length;
    $('#scanMeta').textContent = `${data.target} · ${data.durationMs} ms total · ${data.notice}`;
    $('#findings').innerHTML = (data.findings || []).map(f => `<div class="px-5 py-4"><div class="flex items-start gap-3"><span class="rounded-lg border px-2 py-1 text-[10px] font-black uppercase ${severityClass(f.severity)}">${esc(f.severity)}</span><div><div class="font-semibold">${esc(f.title)}</div><div class="mt-1 text-sm text-zinc-500">${esc(f.detail)}</div></div></div></div>`).join('') || '<div class="px-5 py-10 text-center text-emerald-300">No suspicious heuristic findings were detected.</div>';
    $('#providers').textContent = JSON.stringify(data.providers || {}, null, 2);
    const n = data.node || {}; $('#route').innerHTML = `${flag(n.country)} <b>${esc(n.country)}</b> · ${esc(n.region)} · <span class="font-mono">${esc(n.protocol)}</span> · ${esc(n.address)} · ${n.latencyMs ?? '—'} ms`;
  } catch (error) {
    $('#scanMeta').textContent = error.message; $('#findings').innerHTML = `<div class="px-5 py-10 text-center text-rose-300">${esc(error.message)}</div>`;
  } finally { $('#scanBtn').disabled = false; $('#scanBtn').textContent = 'Scan'; }
});
init().catch(error => { $('#providerInfo').textContent = error.message; });
