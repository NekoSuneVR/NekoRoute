const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const flag = code => code && code.length === 2 ? [...code].map(c => String.fromCodePoint(127397 + c.charCodeAt())).join('') : '🌐';
const regions = ['North America','South America','Europe','Africa','Asia','Oceania','Other'];
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
  $('#regionSelect').innerHTML = '<option value="">All regions</option>' + regions.map(r => `<option>${r}</option>`).join('');
  const countries = Object.entries(stats?.byCountry || {}).sort((a,b) => a[0].localeCompare(b[0]));
  $('#countrySelect').innerHTML = '<option value="">All countries</option>' + countries.map(([c,n]) => `<option value="${esc(c)}">${flag(c)} ${esc(c)} · ${n}</option>`).join('');
}

async function loadNodes() {
  const q = new URLSearchParams({ status:'online', limit:'250' });
  if ($('#regionSelect').value) q.set('region', $('#regionSelect').value);
  if ($('#countrySelect').value) q.set('country', $('#countrySelect').value);
  if ($('#protocolSelect').value) q.set('protocol', $('#protocolSelect').value);
  const res = await fetch('/api/proxies?' + q);
  const nodes = await res.json();
  $('#nodeSelect').innerHTML = '<option value="">Auto / multiple</option>' + nodes.map(n => `<option value="${esc(n.ref)}">${flag(n.country)} ${esc(n.country)} · ${esc(n.protocol)} · ${esc(n.address)} · ${n.latencyMs ?? '—'}ms</option>`).join('');
}

function renderSummary(results) {
  const count = test => results.filter(test).length;
  $('#sumTested').textContent = results.length;
  $('#sum2xx').textContent = count(r => r.statusCode >= 200 && r.statusCode < 300);
  $('#sum3xx').textContent = count(r => r.statusCode >= 300 && r.statusCode < 400);
  $('#sum4xx').textContent = count(r => r.statusCode >= 400 && r.statusCode < 500);
  $('#sum5xx').textContent = count(r => r.statusCode >= 500);
  $('#sumErrors').textContent = count(r => !r.ok || r.statusCode == null);
}

function renderRows(results) {
  $('#resultRows').innerHTML = results.map(r => {
    const n = r.node || {};
    const code = r.statusCode == null ? 'ERR' : r.statusCode;
    return `<tr class="hover:bg-emerald-500/[.025]">
      <td class="px-5 py-3"><span class="inline-flex rounded-lg border px-2.5 py-1 font-mono text-xs font-black ${statusClass(r.statusCode)}">${esc(code)}</span><div class="mt-1 text-xs text-zinc-600">${esc(r.statusText || '')}</div></td>
      <td class="px-4 py-3">${flag(n.country)} <span class="font-semibold">${esc(n.country)}</span><div class="text-xs text-zinc-600">${esc(n.region)} · ${esc(n.city)}</div></td>
      <td class="px-4 py-3 font-mono text-xs text-zinc-300">${esc(n.address)}</td>
      <td class="px-4 py-3"><span class="rounded-lg border border-zinc-800 bg-black/20 px-2 py-1 font-mono text-xs">${esc(n.protocol)}</span></td>
      <td class="px-4 py-3">${r.latencyMs == null ? '—' : `${r.latencyMs} ms`}</td>
      <td class="max-w-[250px] truncate px-4 py-3 text-xs text-zinc-500" title="${esc(r.location || '')}">${esc(r.location || '—')}</td>
      <td class="px-5 py-3 text-xs ${r.ok ? 'text-zinc-400' : 'text-rose-300'}">${esc(r.error || (r.contentType || 'Response received'))}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="7" class="px-5 py-12 text-center text-zinc-500">No results.</td></tr>';
}

async function init() {
  const [statsRes, configRes] = await Promise.all([fetch('/api/stats'), fetch('/api/config')]);
  stats = await statsRes.json();
  const config = await configRes.json();
  fillFilters();
  $('#allowlistInfo').textContent = `Public availability tester · HTTP/HTTPS ports 80/443 only · private/reserved networks blocked · maximum ${config.matrixMaxNodes || 12} proxies per run · rate limits apply`; 
  await loadNodes();
}

for (const id of ['regionSelect','countrySelect','protocolSelect']) $(id.startsWith('#') ? id : '#'+id).addEventListener('change', loadNodes);

$('#runBtn').addEventListener('click', async () => {
  const body = {
    url: $('#testUrl').value,
    region: $('#regionSelect').value || undefined,
    country: $('#countrySelect').value || undefined,
    protocol: $('#protocolSelect').value || undefined,
    nodeRef: $('#nodeSelect').value || undefined,
    limit: Number($('#limitSelect').value || 8)
  };
  $('#runBtn').disabled = true;
  $('#runBtn').textContent = 'Testing…';
  $('#resultMeta').textContent = 'Running requests through selected exits…';
  try {
    const res = await fetch('/api/test-matrix', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    lastResult = data;
    renderSummary(data.results || []);
    renderRows(data.results || []);
    $('#resultMeta').textContent = `${data.tested} proxies · ${data.durationMs} ms total · ${data.target}`;
  } catch (error) {
    $('#resultMeta').textContent = error.message;
    $('#resultRows').innerHTML = `<tr><td colspan="7" class="px-5 py-12 text-center text-rose-300">${esc(error.message)}</td></tr>`;
  } finally {
    $('#runBtn').disabled = false;
    $('#runBtn').textContent = 'Run test';
  }
});

$('#copyBtn').addEventListener('click', async () => {
  if (!lastResult) return;
  await navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2));
  $('#copyBtn').textContent = 'Copied';
  setTimeout(() => $('#copyBtn').textContent = 'Copy JSON', 1200);
});

init().catch(error => { $('#allowlistInfo').textContent = error.message; });
