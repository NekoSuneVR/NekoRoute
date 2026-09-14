import dns from 'node:dns/promises';
import net from 'node:net';

function isPrivateIp(ip) {
  if (!net.isIP(ip)) return true;
  if (ip.includes(':')) {
    const n = ip.toLowerCase();
    return n === '::1' || n.startsWith('fc') || n.startsWith('fd') || n.startsWith('fe80:');
  }
  const [a,b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    a >= 224;
}

function hostAllowed(hostname, allowedHosts) {
  const h = hostname.toLowerCase().replace(/\.$/, '');
  return allowedHosts.some(base => h === base || h.endsWith(`.${base}`));
}

export async function validateTarget(rawUrl, allowedHosts) {
  let url;
  try { url = new URL(rawUrl); } catch { throw new Error('Invalid URL'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP/HTTPS URLs are allowed');
  if (url.username || url.password) throw new Error('Credentials in URLs are not allowed');
  if (!hostAllowed(url.hostname, allowedHosts)) throw new Error('Target hostname is not in ALLOWED_TEST_HOSTS');

  const records = await dns.lookup(url.hostname, { all: true, verbatim: true });
  if (!records.length) throw new Error('Target hostname did not resolve');
  for (const record of records) {
    if (isPrivateIp(record.address)) throw new Error('Target resolves to a private/reserved network');
  }
  return url;
}
