const DEFAULT_ORIGINS = ['https://proxyweb.nekosunevr.co.uk'];
const routes = new Map(); // tabId -> { proxy, origins:Set<string> }
let privacySnapshot = null;

async function settings() {
  const data = await browser.storage.local.get(['allowedOrigins','leakProtection']);
  const values = Array.isArray(data.allowedOrigins) ? data.allowedOrigins : DEFAULT_ORIGINS;
  return {
    allowedOrigins: values.map(v => { try { return new URL(v).origin; } catch { return null; } }).filter(Boolean),
    leakProtection: data.leakProtection !== false
  };
}

function proxyInfo(raw) {
  const type = String(raw?.type || '').toLowerCase();
  if (!['http','https','socks','socks4'].includes(type)) throw new Error(`Unsupported proxy type: ${type}`);
  const host = String(raw?.host || '').trim();
  const port = Number(raw?.port);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid proxy host/port');
  return {
    type,
    host,
    port,
    proxyDNS: Boolean(raw?.proxyDNS) && (type === 'socks' || type === 'socks4'),
    failoverTimeout: Math.max(1, Math.min(30, Number(raw?.failoverTimeout || 8))),
    connectionIsolationKey: `nekoroute-${crypto.randomUUID()}`
  };
}

async function enableLeakProtection() {
  const cfg = await settings();
  if (!cfg.leakProtection || privacySnapshot) return;
  privacySnapshot = {};
  try {
    const prediction = await browser.privacy.network.networkPredictionEnabled.get({});
    privacySnapshot.networkPredictionEnabled = prediction.value;
    if (['controllable_by_this_extension','controlled_by_this_extension'].includes(prediction.levelOfControl)) {
      await browser.privacy.network.networkPredictionEnabled.set({ value:false });
    }
  } catch {}
  try {
    const rtc = await browser.privacy.network.webRTCIPHandlingPolicy.get({});
    privacySnapshot.webRTCIPHandlingPolicy = rtc.value;
    if (['controllable_by_this_extension','controlled_by_this_extension'].includes(rtc.levelOfControl)) {
      await browser.privacy.network.webRTCIPHandlingPolicy.set({ value:'proxy_only' });
    }
  } catch {}
}

async function restoreLeakProtection() {
  if (routes.size || !privacySnapshot) return;
  const snapshot = privacySnapshot; privacySnapshot = null;
  try { if (typeof snapshot.networkPredictionEnabled === 'boolean') await browser.privacy.network.networkPredictionEnabled.set({ value:snapshot.networkPredictionEnabled }); } catch {}
  try { if (snapshot.webRTCIPHandlingPolicy) await browser.privacy.network.webRTCIPHandlingPolicy.set({ value:snapshot.webRTCIPHandlingPolicy }); } catch {}
}

function routeForRequest(details) {
  const direct = routes.get(details.tabId);
  if (direct) return direct;
  // Some browser/download requests can lose tabId. When Firefox still supplies an
  // origin/document URL, inherit the route from the NekoRoute-opened tab.
  for (const candidate of [details.documentUrl, details.originUrl]) {
    if (!candidate) continue;
    let origin;
    try { origin = new URL(candidate).origin; } catch { continue; }
    for (const route of routes.values()) if (route.origins.has(origin)) return route;
  }
  return null;
}

browser.proxy.onRequest.addListener(details => {
  const route = routeForRequest(details);
  if (!route) return { type:'direct' };
  // Explicit null terminator prevents an unreachable proxy from silently falling
  // back to the user's direct connection.
  return [route.proxy, null];
}, { urls:['<all_urls>'] });

browser.proxy.onError.addListener(error => console.error('[NekoRoute Bridge] proxy error', error));

browser.tabs.onUpdated.addListener((tabId, changeInfo) => {
  const route = routes.get(tabId);
  if (!route || !changeInfo.url) return;
  try { route.origins.add(new URL(changeInfo.url).origin); } catch {}
});

browser.tabs.onRemoved.addListener(tabId => {
  routes.delete(tabId);
  restoreLeakProtection();
});

browser.tabs.onCreated.addListener(tab => {
  if (tab.openerTabId != null && routes.has(tab.openerTabId)) {
    const parent = routes.get(tab.openerTabId);
    routes.set(tab.id, { proxy:parent.proxy, origins:new Set(parent.origins) });
  }
});

async function openTicket(ticketUrl) {
  const ticket = new URL(ticketUrl);
  if (!['http:','https:'].includes(ticket.protocol) || !ticket.pathname.startsWith('/api/v1/browser-ticket/')) throw new Error('Invalid NekoRoute ticket URL');
  const cfg = await settings();
  if (!cfg.allowedOrigins.includes(ticket.origin)) throw new Error(`This NekoRoute origin is not trusted by the extension: ${ticket.origin}`);
  const response = await fetch(ticket.toString(), { cache:'no-store', credentials:'omit' });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Ticket HTTP ${response.status}`);
  const proxy = proxyInfo(data.proxy);
  const target = new URL(data.target);
  if (!['http:','https:'].includes(target.protocol)) throw new Error('Ticket target is not HTTP/HTTPS');
  await enableLeakProtection();
  const tab = await browser.tabs.create({ url:'about:blank', active:true });
  routes.set(tab.id, { proxy, origins:new Set([target.origin]) });
  await browser.tabs.update(tab.id, { url:target.toString() });
  const n = data.node || {};
  return { tabId:tab.id, nodeLabel:`${n.countryName || n.country || 'Unknown'} · ${n.protocol || data.proxy.type} · ${n.city || 'Unknown'}` };
}

browser.runtime.onMessage.addListener(async message => {
  if (message?.type === 'NEKOROUTE_OPEN_TICKET') {
    try { return { ok:true, ...(await openTicket(message.ticketUrl)) }; }
    catch (error) { return { ok:false, error:String(error?.message || error) }; }
  }
  if (message?.type === 'NEKOROUTE_IS_ORIGIN_ALLOWED') {
    const origin = String(message.origin || '');
    return { ok:(await settings()).allowedOrigins.includes(origin) };
  }
  return undefined;
});

browser.action.onClicked.addListener(async () => {
  const cfg = await settings();
  const base = cfg.allowedOrigins[0] || DEFAULT_ORIGINS[0];
  await browser.tabs.create({ url:`${base}/browser` });
});
