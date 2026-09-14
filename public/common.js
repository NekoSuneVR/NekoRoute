const regionNames = (() => {
  try { return new Intl.DisplayNames(['en'], { type: 'region' }); }
  catch { return null; }
})();

export const regions = ['North America','South America','Europe','Africa','Asia','Oceania','Other'];

export const esc = s => String(s ?? '').replace(/[&<>"']/g, m => ({
  '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
}[m]));

export function normalizeCountryCode(code) {
  const c = String(code || 'XX').trim().toUpperCase();
  if (c === 'UK') return 'GB';
  return /^[A-Z]{2}$/.test(c) ? c : 'XX';
}

export function flag(code) {
  const c = normalizeCountryCode(code);
  if (c === 'XX') return '🌐';
  return [...c].map(ch => String.fromCodePoint(127397 + ch.charCodeAt())).join('');
}

export function countryName(code) {
  const c = normalizeCountryCode(code);
  if (c === 'XX') return 'Unknown';
  try {
    const name = regionNames?.of(c);
    return name && name !== c ? name : c;
  } catch {
    return c;
  }
}

export function countryLabel(code, { withCode = true } = {}) {
  const c = normalizeCountryCode(code);
  const name = countryName(c);
  return `${flag(c)} ${name}${withCode && c !== 'XX' ? ` (${c})` : ''}`;
}


export function createNodePager({
  select,
  previous,
  next,
  label,
  getFilters,
  pageSize = 50,
  autoLabel = 'Best healthy node automatically'
}) {
  const state = { page: 1, pages: 1, total: 0, loading: false };

  function sync() {
    if (previous) previous.disabled = state.loading || state.page <= 1;
    if (next) next.disabled = state.loading || state.page >= state.pages;
    if (label) label.textContent = state.total ? `Page ${state.page} of ${state.pages} · ${state.total} nodes` : 'No matching nodes';
  }

  async function load({ reset = false } = {}) {
    if (!select || state.loading) return;
    if (reset) state.page = 1;
    state.loading = true;
    sync();
    const q = new URLSearchParams({ status:'online', page:String(state.page), pageSize:String(pageSize) });
    const filters = getFilters?.() || {};
    for (const [key, raw] of Object.entries(filters)) {
      const v = String(raw ?? '').trim();
      if (v) q.set(key, v);
    }
    try {
      const res = await fetch('/api/v1/nodes?' + q);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      state.page = Number(data.page || 1);
      state.pages = Number(data.pages || 1);
      state.total = Number(data.total || 0);
      const items = Array.isArray(data.items) ? data.items : [];
      select.innerHTML = `<option value="">${esc(autoLabel)}</option>` + items.map(n =>
        `<option value="${esc(n.ref)}">${esc(countryLabel(n.country))} · ${esc(n.protocol)} · ${esc(n.city || 'Unknown')} · ${n.latencyMs ?? '—'}ms</option>`
      ).join('');
    } finally {
      state.loading = false;
      sync();
    }
  }

  previous?.addEventListener('click', async () => {
    if (state.page <= 1) return;
    state.page--;
    await load();
  });
  next?.addEventListener('click', async () => {
    if (state.page >= state.pages) return;
    state.page++;
    await load();
  });
  sync();
  return { state, load, reset: () => load({ reset:true }) };
}
