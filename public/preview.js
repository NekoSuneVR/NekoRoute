const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const flag = code => code && code.length === 2 ? [...code].map(c => String.fromCodePoint(127397 + c.charCodeAt())).join('') : '🌐';
const regions = ['North America','South America','Europe','Africa','Asia','Oceania','Other'];
let stats = null;
let session = null;
let history = [];
let historyIndex = -1;

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
  $('#nodeSelect').innerHTML = '<option value="">Best healthy node automatically</option>' + nodes.map(n => `<option value="${esc(n.ref)}">${flag(n.country)} ${esc(n.country)} · ${esc(n.protocol)} · ${esc(n.address)} · ${n.latencyMs ?? '—'}ms</option>`).join('');
}

function updateHistoryButtons() {
  $('#backBtn').disabled = historyIndex <= 0;
  $('#forwardBtn').disabled = historyIndex < 0 || historyIndex >= history.length - 1;
  $('#reloadBtn').disabled = !session || historyIndex < 0;
}

function frameUrl(url) {
  return `/api/preview/${encodeURIComponent(session.sessionId)}?url=${encodeURIComponent(url)}`;
}

function navigate(url, { push = true } = {}) {
  if (!session) return;
  $('#urlInput').value = url;
  if (push) {
    history = history.slice(0, historyIndex + 1);
    history.push(url);
    historyIndex = history.length - 1;
  }
  $('#frameStatus').textContent = 'Loading through proxy…';
  $('#previewFrame').src = frameUrl(url);
  updateHistoryButtons();
}

async function createSession() {
  const body = {
    url: $('#urlInput').value,
    region: $('#regionSelect').value || undefined,
    country: $('#countrySelect').value || undefined,
    protocol: $('#protocolSelect').value || undefined,
    nodeRef: $('#nodeSelect').value || undefined
  };
  const res = await fetch('/api/preview-session', { method:'POST', headers:{'content-type':'application/json','x-admin-token':$('#adminToken').value}, body:JSON.stringify(body) });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  session = data;
  history = [];
  historyIndex = -1;
  const n = data.node || {};
  $('#routeInfo').innerHTML = `${flag(n.country)} <b class="text-zinc-200">${esc(n.country)}</b> · ${esc(n.region)} · <span class="font-mono">${esc(n.protocol)}</span> · ${esc(n.address)} · ${n.latencyMs ?? '—'} ms`;
  navigate(data.url, { push:true });
}

for (const id of ['regionSelect','countrySelect','protocolSelect']) $('#'+id).addEventListener('change', loadNodes);
$('#goBtn').addEventListener('click', async () => {
  $('#goBtn').disabled = true;
  $('#goBtn').textContent = 'Opening…';
  try { await createSession(); }
  catch (error) { $('#routeInfo').textContent = error.message; $('#frameStatus').textContent = 'Preview failed'; }
  finally { $('#goBtn').disabled = false; $('#goBtn').textContent = 'Open'; }
});
$('#urlInput').addEventListener('keydown', event => { if (event.key === 'Enter') $('#goBtn').click(); });
$('#backBtn').addEventListener('click', () => { if (historyIndex > 0) { historyIndex--; navigate(history[historyIndex], { push:false }); } });
$('#forwardBtn').addEventListener('click', () => { if (historyIndex < history.length - 1) { historyIndex++; navigate(history[historyIndex], { push:false }); } });
$('#reloadBtn').addEventListener('click', () => { if (historyIndex >= 0) navigate(history[historyIndex], { push:false }); });
$('#previewFrame').addEventListener('load', () => { $('#frameStatus').textContent = session ? `Preview active · session expires ${new Date(session.expiresAt).toLocaleTimeString()}` : 'Safe preview'; });
window.addEventListener('message', event => {
  if (event.source !== $('#previewFrame').contentWindow) return;
  if (event.data?.type === 'nekoroute-preview-nav' && typeof event.data.url === 'string') navigate(event.data.url, { push:true });
});

async function init() {
  const statsRes = await fetch('/api/stats');
  stats = await statsRes.json();
  fillFilters();
  await loadNodes();
  updateHistoryButtons();
}
init().catch(error => { $('#routeInfo').textContent = error.message; });
