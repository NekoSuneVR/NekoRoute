(async () => {
  if (!document.querySelector('meta[name="nekoroute-bridge"][content="v1"]')) return;
  let allowed = false;
  try {
    const result = await browser.runtime.sendMessage({ type:'NEKOROUTE_IS_ORIGIN_ALLOWED', origin:location.origin });
    allowed = Boolean(result?.ok);
  } catch {}
  if (!allowed) return;

  const ready = () => window.postMessage({ source:'nekoroute-firefox-bridge', type:'NEKOROUTE_BRIDGE_READY' }, location.origin);
  ready();
  window.addEventListener('message', async event => {
    if (event.source !== window || event.origin !== location.origin || event.data?.source !== 'nekoroute-web') return;
    if (event.data.type === 'NEKOROUTE_BRIDGE_PING') return ready();
    if (event.data.type !== 'NEKOROUTE_OPEN_FIREFOX') return;
    let result;
    try {
      result = await browser.runtime.sendMessage({ type:'NEKOROUTE_OPEN_TICKET', ticketUrl:String(event.data.ticketUrl || '') });
    } catch (error) {
      result = { ok:false, error:String(error?.message || error) };
    }
    window.postMessage({ source:'nekoroute-firefox-bridge', type:'NEKOROUTE_BRIDGE_RESULT', ...result }, location.origin);
  });
})();
