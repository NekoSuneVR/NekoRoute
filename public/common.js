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
