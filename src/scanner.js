import http from 'node:http';
import https from 'node:https';
import * as cheerio from 'cheerio';
import { requestViaProxy } from './proxy.js';
import { validatePublicTarget } from './security.js';

function addFinding(findings, severity, title, detail, points) {
  findings.push({ severity, title, detail, points });
}

function riskVerdict(score) {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

async function fetchJson(url, options = {}) {
  const target = new URL(url);
  const lib = target.protocol === 'http:' ? http : https;
  return new Promise((resolve, reject) => {
    const req = lib.request(target, { method: options.method || 'GET', headers: options.headers || {}, timeout: options.timeoutMs || 8000 }, res => {
      const chunks = [];
      let bytes = 0;
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 1024 * 1024) return req.destroy(new Error('provider response too large'));
        chunks.push(chunk);
      });
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let body = null;
        try { body = raw ? JSON.parse(raw) : {}; } catch { body = { raw: raw.slice(0, 1000) }; }
        resolve({ statusCode: res.statusCode || 0, body });
      });
    });
    req.on('timeout', () => req.destroy(new Error('provider request timed out')));
    req.on('error', reject);
    req.end(options.body || undefined);
  });
}

async function providerReputation(targetUrl, config) {
  const providers = {};

  if (config.virusTotalApiKey) {
    try {
      const id = Buffer.from(targetUrl).toString('base64url');
      const response = await fetchJson(`https://www.virustotal.com/api/v3/urls/${id}`, {
        headers: { 'x-apikey': config.virusTotalApiKey, accept: 'application/json' }
      });
      if (response.statusCode === 200) {
        const stats = response.body?.data?.attributes?.last_analysis_stats || {};
        providers.virusTotal = {
          available: true,
          malicious: Number(stats.malicious || 0),
          suspicious: Number(stats.suspicious || 0),
          harmless: Number(stats.harmless || 0),
          undetected: Number(stats.undetected || 0),
          lastAnalysisDate: response.body?.data?.attributes?.last_analysis_date || null
        };
      } else if (response.statusCode === 404) {
        providers.virusTotal = { available: true, known: false };
      } else {
        providers.virusTotal = { available: false, error: `HTTP ${response.statusCode}` };
      }
    } catch (error) {
      providers.virusTotal = { available: false, error: String(error.message || error) };
    }
  }

  if (config.googleWebRiskApiKey) {
    try {
      const query = new URL('https://webrisk.googleapis.com/v1/uris:search');
      for (const threat of ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE']) query.searchParams.append('threatTypes', threat);
      query.searchParams.set('uri', targetUrl);
      query.searchParams.set('key', config.googleWebRiskApiKey);
      const response = await fetchJson(query.toString());
      const threats = response.body?.threat?.threatTypes || [];
      providers.googleWebRisk = { available: response.statusCode === 200, threats, expireTime: response.body?.threat?.expireTime || null };
    } catch (error) {
      providers.googleWebRisk = { available: false, error: String(error.message || error) };
    }
  }

  return providers;
}

async function fetchDocument(node, initialUrl, config, redirectsLeft = 3, chain = []) {
  const target = await validatePublicTarget(initialUrl);
  const result = await requestViaProxy(node, target, {
    timeoutMs: config.scanTimeoutMs,
    maxBytes: config.scanMaxBytes,
    headers: {
      accept: 'text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.2',
      'user-agent': 'NekoRoute-SafetyScanner/1.0'
    }
  });
  const nextChain = [...chain, { url: target.toString(), statusCode: result.statusCode }];
  if (result.statusCode >= 300 && result.statusCode < 400 && result.headers.location && redirectsLeft > 0) {
    const next = new URL(result.headers.location, target).toString();
    await validatePublicTarget(next);
    return fetchDocument(node, next, config, redirectsLeft - 1, nextChain);
  }
  return { target, result, chain: nextChain };
}

export async function scanWebsite(node, rawUrl, config) {
  const started = Date.now();
  const { target, result, chain } = await fetchDocument(node, rawUrl, config);
  const contentType = String(result.headers['content-type'] || '').toLowerCase();
  const findings = [];

  if (result.statusCode >= 400) {
    addFinding(findings, 'info', `HTTP ${result.statusCode}`, 'The selected exit received an error response. This can be regional blocking, authentication, rate limiting, or a normal missing page.', 0);
  }

  const securityHeaders = {
    csp: Boolean(result.headers['content-security-policy']),
    hsts: Boolean(result.headers['strict-transport-security']),
    xFrameOptions: Boolean(result.headers['x-frame-options']),
    xContentTypeOptions: Boolean(result.headers['x-content-type-options']),
    referrerPolicy: Boolean(result.headers['referrer-policy']),
    permissionsPolicy: Boolean(result.headers['permissions-policy'])
  };

  if (target.protocol === 'https:' && !securityHeaders.hsts) addFinding(findings, 'low', 'HSTS not present', 'HTTPS is in use but Strict-Transport-Security was not observed.', 3);
  if (!securityHeaders.csp) addFinding(findings, 'low', 'CSP not present', 'No Content-Security-Policy header was observed. This is not proof of compromise, but it reduces browser-side hardening.', 4);

  const page = { title: null, scripts: 0, externalScripts: 0, iframes: 0, forms: 0, externalForms: 0, executableLinks: 0 };
  if (contentType.includes('html') || contentType.includes('xhtml') || !contentType) {
    const html = result.body || '';
    const $ = cheerio.load(html);
    page.title = $('title').first().text().trim().slice(0, 300) || null;
    page.scripts = $('script').length;
    page.externalScripts = $('script[src]').length;
    page.iframes = $('iframe,frame').length;
    page.forms = $('form').length;

    $('form[action]').each((_i, el) => {
      try {
        const action = new URL($(el).attr('action'), target);
        if (action.hostname !== target.hostname) page.externalForms++;
      } catch {}
    });
    if (page.externalForms) addFinding(findings, 'medium', 'Cross-domain form submission', `${page.externalForms} form(s) submit data to a different hostname. Review before entering credentials.`, 14);

    const riskyExt = /\.(?:exe|msi|scr|bat|cmd|ps1|apk|jar|dmg|pkg|iso|img)(?:$|[?#])/i;
    $('a[href]').each((_i, el) => {
      const href = $(el).attr('href') || '';
      if (riskyExt.test(href)) page.executableLinks++;
    });
    if (page.executableLinks) addFinding(findings, 'medium', 'Executable download links', `${page.executableLinks} link(s) point to executable or installable file types.`, Math.min(24, 8 + page.executableLinks * 3));

    if (page.iframes > 4) addFinding(findings, 'low', 'Many embedded frames', `${page.iframes} iframe/frame elements were found. This can be normal for ads/media, but deserves review on an unknown site.`, 5);

    const suspiciousPatterns = [
      [/\beval\s*\(/gi, 'eval() usage'],
      [/\bFunction\s*\(/g, 'dynamic Function() construction'],
      [/\b(?:atob|unescape)\s*\(/gi, 'encoded/obfuscated string decoding'],
      [/String\.fromCharCode\s*\(/g, 'character-code string construction'],
      [/document\.write\s*\(/gi, 'document.write() usage'],
      [/[A-Za-z0-9+/]{600,}={0,2}/g, 'large base64-like blob']
    ];
    for (const [pattern, label] of suspiciousPatterns) {
      const matches = html.match(pattern)?.length || 0;
      if (matches) addFinding(findings, matches > 4 ? 'medium' : 'low', label, `${matches} occurrence(s) found in the fetched HTML. This is heuristic only and can have false positives.`, Math.min(18, 3 + matches * 2));
    }

    const metaRefresh = $('meta[http-equiv="refresh" i]').length;
    if (metaRefresh) addFinding(findings, 'low', 'Meta refresh redirect', `${metaRefresh} meta-refresh directive(s) were found.`, 4);

    const passwordForms = $('input[type="password"]').length;
    if (passwordForms && page.externalForms) addFinding(findings, 'high', 'Password field with cross-domain form', 'A password field is present while at least one form submits to another hostname.', 28);
  } else {
    addFinding(findings, 'info', 'Non-HTML response', `The server returned ${contentType || 'an unknown content type'}, so script/DOM heuristics were not applied.`, 0);
  }

  const providers = await providerReputation(target.toString(), config);
  const vt = providers.virusTotal;
  if (vt?.malicious > 0) addFinding(findings, 'critical', 'VirusTotal detections', `${vt.malicious} engine(s) marked this URL malicious and ${vt.suspicious || 0} suspicious.`, Math.min(60, 30 + vt.malicious * 5));
  const wrThreats = providers.googleWebRisk?.threats || [];
  if (wrThreats.length) addFinding(findings, 'critical', 'Google Web Risk match', `Threat list match: ${wrThreats.join(', ')}.`, 55);

  const score = Math.min(100, findings.reduce((sum, finding) => sum + Number(finding.points || 0), 0));
  const verdict = riskVerdict(score);

  return {
    target: target.toString(),
    requestedUrl: rawUrl,
    statusCode: result.statusCode,
    latencyMs: result.latencyMs,
    contentType: result.headers['content-type'] || null,
    redirectChain: chain,
    securityHeaders,
    page,
    providers,
    findings,
    score,
    verdict,
    durationMs: Date.now() - started
  };
}
